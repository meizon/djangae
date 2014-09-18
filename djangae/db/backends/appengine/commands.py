#STANDARD LIB
from datetime import datetime, date
import logging
import copy
from functools import partial
from itertools import chain, product

#LIBRARIES
from django.core.cache import cache
from django.db.backends.mysql.compiler import SQLCompiler
from django.db import IntegrityError
from django.db.models import Field
from django.db.models.sql.datastructures import EmptyResultSet
from django.db.models.sql.where import AND, OR, Constraint
from django import dispatch
from google.appengine.api import datastore
from google.appengine.api.datastore import Query
from google.appengine.ext import db

#DJANGAE
from djangae.db.exceptions import CouldBeSupportedError, NotSupportedError
from djangae.db.utils import (
    get_datastore_key,
    django_instance_to_entity,
    get_datastore_kind,
    get_prepared_db_value,
    MockInstance,
    get_top_concrete_parent,
    get_concrete_parents,
    has_concrete_parents,
    get_ancestor_field
)
from djangae.indexing import special_indexes_for_column, REQUIRES_SPECIAL_INDEXES, add_special_index
from djangae.utils import on_production, in_testing
from djangae.db import constraints, utils

DJANGAE_LOG = logging.getLogger("djangae")

entity_pre_update = dispatch.Signal(providing_args=["sender", "entity"])
entity_post_update = dispatch.Signal(providing_args=["sender", "entity"])
entity_post_insert = dispatch.Signal(providing_args=["sender", "entity"])
entity_deleted = dispatch.Signal(providing_args=["sender", "entity"])
get_pre_execute = dispatch.Signal(providing_args=["sender", "key"])
query_pre_execute = dispatch.Signal(providing_args=["sender", "query", "aggregate"])

OPERATORS_MAP = {
    'exact': '=',
    'gt': '>',
    'gte': '>=',
    'lt': '<',
    'lte': '<=',

    # The following operators are supported with special code below.
    'isnull': None,
    'in': None,
    'startswith': None,
    'range': None,
}

REVERSE_OP_MAP = {
    '=':'exact',
    '>':'gt',
    '>=':'gte',
    '<':'lt',
    '<=':'lte',
}

INEQUALITY_OPERATORS = frozenset(['>', '<', '<=', '>='])

def get_field_from_column(model, column):
    #FIXME: memoize this
    for field in model._meta.fields:
        if field.column == column:
            return field
    return None

def field_conv_year_only(value):
    value = ensure_datetime(value)
    return datetime(value.year, 1, 1, 0, 0)

def field_conv_month_only(value):
    value = ensure_datetime(value)
    return datetime(value.year, value.month, 1, 0, 0)

def field_conv_day_only(value):
    value = ensure_datetime(value)
    return datetime(value.year, value.month, value.day, 0, 0)

def ensure_datetime(value):
    """ Painfully, sometimes the Datastore returns dates as datetime objects, and sometimes
        it returns them as unix timestamps in microseconds!!
    """
    if isinstance(value, long):
        return datetime.fromtimestamp(value / 1000000)
    return value



FILTER_CMP_FUNCTION_MAP = {
    'exact': lambda a, b: a == b,
    'iexact': lambda a, b: a.lower() == b.lower(),
    'gt': lambda a, b: a > b,
    'lt': lambda a, b: a < b,
    'gte': lambda a, b: a >= b,
    'lte': lambda a, b: a <= b,
    'isnull': lambda a, b: (b and (a is None)) or (a is not None),
    'in': lambda a, b: a in b,
    'startswith': lambda a, b: a.startswith(b),
    'range': lambda a, b: b[0] < a < b[1], #I'm assuming that b is a tuple
    'year': lambda a, b: field_conv_year_only(a) == b,
}


def log_once(logging_call, text, args):
    """
        Only logs one instance of the combination of text and arguments to the passed
        logging function
    """
    identifier = "%s:%s" % (text, args)
    if identifier in log_once.logged:
        return
    logging_call(text % args)
    log_once.logged.add(identifier)

log_once.logged = set()


def parse_constraint(child, connection):
    #First, unpack the constraint
    constraint, op, annotation, value = child
    was_list = isinstance(value, (list, tuple))
    packed, value = constraint.process(op, value, connection)
    alias, column, db_type = packed

    if constraint.field.db_type(connection) in ("bytes", "text"):
        raise NotSupportedError("Text and Blob fields are not indexed by the datastore, so you can't filter on them")

    if op not in REQUIRES_SPECIAL_INDEXES:
        #Don't convert if this op requires special indexes, it will be handled there
        value = [ connection.ops.prep_lookup_value(constraint.field.model, x, constraint.field, constraint=constraint) for x in value]

        #Don't ask me why, but constraint.process on isnull wipes out the value (it returns an empty list)
        # so we have to special case this to use the annotation value instead
        if op == "isnull":
            value = [ annotation ]

        if not was_list:
            value = value[0]
    else:
        if not was_list:
            value = value[0]

        add_special_index(constraint.field.model, column, op) #Add the index if we can (e.g. on dev_appserver)

        if op not in special_indexes_for_column(constraint.field.model, column):
            raise RuntimeError("There is a missing index in your djangaeidx.yaml - \n\n{0}:\n\t{1}: [{2}]".format(
                constraint.field.model, column, op)
            )

        indexer = REQUIRES_SPECIAL_INDEXES[op]
        column = indexer.indexed_column_name(column)
        value = indexer.prep_value_for_query(value)
        op = "exact" #Perhaps this should be supplied by the indexer?

    return column, op, value


def normalize_query(node, connection, negated=False, filtered_columns=None, _inequality_property=None):
    """
        Converts a django_where_tree which is CNF to a DNF for use in the datastore.
        This function does a lot of heavy lifting so optimization is welcome.

        The connection is needed for calculating the values on the literals, it would
        be nice if we can remove that so this only has one task, but it's fine for now
    """
    _inequality_property = _inequality_property if _inequality_property is not None else []

    def check_inequality_usage(_op, _column, _current_inequality):
        if _op in INEQUALITY_OPERATORS:
            if _current_inequality and _current_inequality[0] != _column:
                raise NotSupportedError(
                    "You can only specify inequality filters ({}) on one property. There is already one on {}, you're attempting to use one on {}".format(
                        INEQUALITY_OPERATORS,
                        _current_inequality[0],
                        _column
                    )
                )
            else:
                #We have to use a list, because Python 2.x doesn't have 'nonlocal' :/
                _current_inequality.append(_column)

    if isinstance(node, tuple) and isinstance(node[0], Constraint):
        column, op, value = parse_constraint(node, connection)

        if filtered_columns is not None:
            assert isinstance(filtered_columns, set)
            filtered_columns.add(column)

        if op == 'in': # Explode INs into OR
            if not isinstance(value, (list, tuple, set)):
                raise ValueError("IN queries must be supplied a list of values")

            if negated:
                check_inequality_usage(">", column, _inequality_property)
                return ('OR', [ ('OR', [(column, '>', x), (column, '<', x)]) for x in value ])
            else:
                return ('OR', [(column, '=', x) for x in value])

        if op not in OPERATORS_MAP:
            raise NotSupportedError("Unsupported operator %s" % op)

        _op = OPERATORS_MAP[op]

        check_inequality_usage(_op, column, _inequality_property) #Check we aren't doing an additional inequality

        if negated and _op == '=': # Explode
            check_inequality_usage('>', column, _inequality_property)
            return ('OR', [(column, '>', value), (column, '<', value)])
        elif op == "startswith":
            #You can emulate starts with by adding the last unicode char
            #to the value, then doing <=. Genius.
            if value.endswith("%"):
                value = value[:-1]
            end_value = value[:]
            if isinstance(end_value, str):
                end_value = end_value.decode("utf-8")
            end_value += u'\ufffd'

            check_inequality_usage('>=', column, _inequality_property)
            if not negated:
                return ('AND', [(column, '>=', value), (column, '<', end_value)])
            else:
                return ('OR', [(column, '<', value), (column, '>=', end_value)])

        elif op == "isnull":
            if (value and not negated) or (not value and negated): #We're checking for isnull=True
                #If we are checking that a primary key isnull, then don't do an impossible query!
                if node[0].field.primary_key:
                    raise EmptyResultSet()

                return (column, "=", None)
            else: #We're checking for isnull=False
                check_inequality_usage('>', column, _inequality_property)
                return ('OR', [(column, '>', None), (column, '<', None)])
        elif _op == None:
            raise NotSupportedError("Unhandled lookup type %s" % op)

        return (column, _op, value)
    else:
        if not node.children:
            return []

        if node.negated:
            negated = True
        if len(node.children) > 1: # If there is more than one child then attempt to reduce
            exploded = (node.connector, [
                normalize_query(child, connection, negated=negated, filtered_columns=filtered_columns, _inequality_property=_inequality_property)
                for child in node.children
            ])

            if node.connector == 'AND':
                if len(exploded[1]) == 2 and [x[0] for x in exploded[1]].count('OR') == 1:
                    _or = [x for x in exploded[1] if x[0] == 'OR' ][0]
                    tar = [x for x in exploded[1] if x[0] != 'OR'][0]
                    prods = [('AND', list(x)) for x in product([tar], _or[1])]
                    finals = []
                    for prod in prods:
                        if any(x[0] == 'AND' for x in prod[1]):
                            _ands = [x for x in prod[1] if x[0] == 'AND']
                            tar = [x for x in prod[1] if x[0] != 'AND']
                            finals.append(('AND', list(chain(_ands[0][1], tar))))
                        else:
                            finals.append(prod)
                    return ('OR', finals)
                elif len(exploded[1]) == 2 and [x[0] for x in exploded[1]].count('OR') == 2:
                    ret = ('OR', [ ('AND', list(x)) for x in product(exploded[1][0][1], exploded[1][1][1]) ])
                    return ret

            elif node.connector == 'OR':
                if all(x[0] == 'OR' for x in exploded[1]):
                    return ('OR', list(chain.from_iterable((x[1] for x in exploded[1]))))
            return exploded
        else:
            exploded = normalize_query(
                node.children[0],
                connection,
                negated=negated,
                filtered_columns=filtered_columns,
                _inequality_property=_inequality_property
            )
            if len(exploded[1]) and exploded[0] == exploded[1][0][0]: # crush any single child 'OR' or 'AND' hangover
              return (exploded[0], [x for x in exploded[1][0][1]])
            return exploded



class QueryByKeys(object):
    def __init__(self, query, keys, ordering):
        self.query = query
        self.keys = keys
        self.ordering = ordering
        self._Query__kind = query._Query__kind

    def Run(self, limit, offset):

        results = sorted((x for x in datastore.Get(self.keys) if x is not None), cmp=partial(utils.django_ordering_comparison, self.ordering))

        if offset:
            results = results[offset:]

        if limit is not None:
            results = results[:limit]

        return ( x for x in results if utils.entity_matches_query(x, self.query) )

    def Count(self, limit, offset):
        return len([ x for x in self.Run(limit, offset) ])

class NoOpQuery(object):
    def Run(self, limit, offset):
        return []

    def Count(self, limit, offset):
        return 0

class SelectCommand(object):
    def __init__(self, connection, query, keys_only=False):

        self.original_query = query
        self.connection = connection

        self.limits = (query.low_mark, query.high_mark)

        opts = query.get_meta()

        self.distinct = query.distinct
        self.distinct_values = set()
        self.distinct_on_field = None
        self.distinct_field_convertor = None
        self.queried_fields = []
        self.model = query.model
        self.pk_col = opts.pk.column
        self.is_count = query.aggregates
        self.extra_select = query.extra_select
        self._set_db_table()
        self.ancestor = None

        if not query.default_ordering:
            self.ordering = query.order_by
        else:
            self.ordering = query.order_by or opts.ordering

        if self.ordering:
            ordering = [ x for x in self.ordering if not (isinstance(x, basestring) and "__" in x) ]
            if len(ordering) < len(self.ordering):
                if not on_production() and not in_testing():
                    diff = set(self.ordering) - set(ordering)
                    log_once(DJANGAE_LOG.warning, "The following orderings were ignored as cross-table orderings are not supported on the datastore: %s", diff)
                self.ordering = ordering

        #If the query uses defer()/only() then we need to process deferred. We have to get all deferred columns
        # for all (concrete) inherited models and then only include columns if they appear in that list
        deferred_columns = {}
        query.deferred_to_data(deferred_columns, query.deferred_to_columns_cb)
        inherited_db_tables = [ x._meta.db_table for x in get_concrete_parents(self.model) ]
        only_load = list(chain(*[ list(deferred_columns.get(x, [])) for x in inherited_db_tables ]))

        if query.select:
            for x in query.select:
                if hasattr(x, "field"):
                    #In Django 1.6+ 'x' above is a SelectInfo (which is a tuple subclass), whereas in 1.5 it's a tuple
                    # in 1.6 x[1] == Field, but 1.5 x[1] == unicode (column name)
                    if x.field is None:
                        column = x.col.col[1] #This is the column we are getting

                        lookup_type = x.col.lookup_type

                        self.distinct_on_field = column

                        #This whole section of code is weird, and is probably better implemented as a custom Query type (like QueryByKeys)
                        # basically, appengine gives back dates as a time since the epoch, we convert it to a date, then floor it, then convert it back
                        # in our transform function. The transform is applied when the results are read back so that only distinct values are returned.
                        # this is very hacky...
                        def date_to_epoch(d):
                            import calendar
                            return int(calendar.timegm(d.timetuple()) * 1000000)

                        if lookup_type == "year":
                            def year_transform(value):
                                value = self.connection.ops.value_from_db_date(value)
                                return date_to_epoch(date(value.year, 1, 1)) if value else None

                            self.distinct_field_convertor = year_transform
                        elif lookup_type == "month":
                            def month_transform(value):
                                value = self.connection.ops.value_from_db_date(value)
                                return date_to_epoch(date(value.year, value.month, 1)) if value else None

                            self.distinct_field_convertor = month_transform
                        elif lookup_type == "day":
                            def day_transform(value):
                                value = self.connection.ops.value_from_db_date(value)
                                return date_to_epoch(value) if value else None

                            self.distinct_field_convertor = day_transform
                        else:
                            raise CouldBeSupportedError("Unhandled lookup_type %s" % lookup_type)
                    else:
                        column = x.field.column
                else:
                    column = x[1]

                if only_load and column not in only_load:
                    continue

                self.queried_fields.append(column)
        else:
            self.queried_fields = [ x.column for x in opts.fields if (not only_load) or (x.column in only_load) ]

        self.keys_only = keys_only or self.queried_fields == [ opts.pk.column ]

        assert self.queried_fields

        #Projection queries don't return results unless all projected fields are
        #indexed on the model. This means if you add a field, and all fields on the model
        #are projectable, you will never get any results until you've resaved all of them.

        #Because it's not possible to detect this situation, we only try a projection query if a
        #subset of fields was specified (e.g. values_list('bananas')) which makes the behaviour a
        #bit more predictable. It would be nice at some point to add some kind of force_projection()
        #thing on a queryset that would do this whenever possible, but that's for the future, maybe.
        try_projection = bool(self.queried_fields)

        self.excluded_pks = set()

        self.has_inequality_filter = False
        self.all_filters = []
        self.results = None

        self.gae_query = None

        self._validate_query_is_possible(query)

        projection_fields = []

        if try_projection:
            for field in self.queried_fields:
                #We don't include the primary key in projection queries...
                if field == self.pk_col:
                    continue

                #Text and byte fields aren't indexed, so we can't do a
                #projection query
                f = get_field_from_column(self.model, field)
                if not f:
                    raise CouldBeSupportedError("Attemping a cross-table select or dates query, or something?!")
                assert f #If this happens, we have a cross-table select going on! #FIXME
                db_type = f.db_type(connection)

                if db_type in ("bytes", "text"):
                    projection_fields = []
                    break

                projection_fields.append(field)

        self.projection = list(set(projection_fields)) or None
        if opts.parents:
            self.projection = None

        columns = set()
        self.where = normalize_query(query.where, self.connection, filtered_columns=columns)
        #DISABLE PROJECTION IF WE ARE FILTERING ON ONE OF THE PROJECTION_FIELDS
        for field in self.projection or []:
            if field in columns:
                self.projection = None
                break

        try:
            #If the PK was queried, we switch it in our queried
            #fields store with __key__
            pk_index = self.queried_fields.index(self.pk_col)
            self.queried_fields[pk_index] = "__key__"

            #If the only field queried was the key, then we can do a keys_only
            #query
            self.keys_only = len(self.queried_fields) == 1
        except ValueError:
            pass

    def execute(self):
        #if not self.included_pks:
        self.gae_query = self._build_gae_query()
        self.results = None
        self.query_done = False
        self.aggregate_type = "count" if self.is_count else None
        self._do_fetch()

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return self.__repr__() == other.__repr__()

    def __repr__(self):
        return "<SelectCommand - SELECT {} FROM {} WHERE {}>".format(
            ", ".join(self.queried_fields or []),
            self.db_table,
            self.where
        )

    def _set_db_table(self):
        """ Work out which Datstore kind we should actually be querying. This allows for poly
            models, i.e. non-abstract parent models which we support by storing all fields for
            both the parent model and its child models on the parent table.
        """
        inheritance_root = get_top_concrete_parent(self.model)
        self.db_table = inheritance_root._meta.db_table

    def _validate_query_is_possible(self, query):
        """ Given the *django* query, check the following:
            - The query only has one inequality filter
            - The query does no joins
            - The query ordering is compatible with the filters
        """
        #Check for joins
        if query.count_active_tables() > 1:
            raise NotSupportedError("""
                The appengine database connector does not support JOINs. The requested join map follows\n
                %s
            """ % query.join_map)

        if query.aggregates:
            if query.aggregates.keys() == [ None ]:
                if query.aggregates[None].col != "*":
                    raise NotSupportedError("Counting anything other than '*' is not supported")
            else:
                raise NotSupportedError("Unsupported aggregate query")

    def _build_gae_query(self):
        """ Build and return the Datstore Query object. """
        query_kwargs = {
            "kind": str(self.db_table)
        }

        if self.distinct:
            query_kwargs["distinct"] = True

        if self.keys_only:
            query_kwargs["keys_only"] = self.keys_only
        elif self.projection:
            query_kwargs["projection"] = self.projection

        query = Query(
            **query_kwargs
        )

        if has_concrete_parents(self.model) and not self.model._meta.proxy:
            query["class ="] = self.model._meta.db_table

        ordering = []
        for order in self.ordering:
            if isinstance(order, int):
                direction = datastore.Query.ASCENDING if order == 1 else datastore.Query.DESCENDING
                order = self.queried_fields[0]
            else:
                direction = datastore.Query.DESCENDING if order.startswith("-") else datastore.Query.ASCENDING
                order = order.lstrip("-")

            if order == self.model._meta.pk.column or order == "pk":
                order = "__key__"
            ordering.append((order, direction))

        def process_and_branch(query, and_branch):
            for column, op, value in and_branch[-1]:
                if column == self.pk_col:
                    column = "__key__"

                    #FIXME: This EmptyResultSet check should happen during normalization so that Django doesn't count it as a query
                    if op == "=" and "__key__ =" in query:
                        #We've already done an exact lookup on a key, this query can't return anything!
                        raise EmptyResultSet()

                    if not isinstance(value, datastore.Key):
                        value = get_datastore_key(self.model, value)

                key = "%s %s" % (column, op)
                if key in query:
                    query[key] = [ query[key], value ]
                else:
                    query[key] = value

        if self.where and self.where[-1]:
            queries = []

            #If there is a single filter, we make it out it's an OR with only one branch
            #just so that the code below is simpler
            if isinstance(self.where, tuple) and len(self.where) == 3:
                self.where = ('OR', [(u'AND', [ self.where ])])
            elif isinstance(self.where, tuple) and self.where[0] == 'AND':
                self.where = ('OR', [self.where])
            elif isinstance(self.where, tuple) and self.where[0] == 'OR' and isinstance(self.where[1][0], tuple) and self.where[1][0][0] != 'AND':
                self.where = ('OR', [ ('AND', [x]) for x in self.where[-1] ])

            operator = self.where[0]
            assert operator == 'OR'
            #print query._Query__kind, self.where

            for and_branch in self.where[1]:
                #Duplicate the query for all the "OR"s
                queries.append(Query(**query_kwargs))
                queries[-1].update(query) #Make sure we copy across filters (e.g. class =)
                try:
                    process_and_branch(queries[-1], and_branch)
                except EmptyResultSet:
                    return NoOpQuery()

            def all_queries_same_except_key(_queries):
                """
                    Returns True if all queries in the list of queries filter on the same thing
                    except for "__key__ =". Determine if we can do a Get basically.
                """
                test = _queries[0]

                for qry in _queries:
                    if "__key__ =" not in qry.keys():
                        return False

                    if qry._Query__kind != test._Query__kind:
                        return False

                    if qry.keys() != test.keys():
                        return False

                    for k, v in qry.items():
                        if k.startswith("__key__"):
                            continue

                        if v != test[k]:
                            return False
                return True

            if all_queries_same_except_key(queries):
                included_pks = [ qry["__key__ ="] for qry in queries ]
                query = QueryByKeys(queries[0], included_pks, ordering) #Just use whatever query to determine the matches
            else:
                if len(queries) > 1:
                    query = datastore.MultiQuery(queries, ordering)
                else:
                    query = queries[0]
                    query.Order(*ordering)
        else:
            query.Order(*ordering)

        DJANGAE_LOG.debug("Select query: {0}, {1}".format(self.model.__name__, self.where))

        return query

    def _do_fetch(self):
        assert not self.results

        self.results = self._run_query(
            aggregate_type=self.aggregate_type,
            start=self.limits[0],
            limit=None if self.limits[1] is None else (self.limits[1] - (self.limits[0] or 0))
        )

        self.query_done = True

    def _run_query(self, limit=None, start=None, aggregate_type=None):
        query_pre_execute.send(sender=self.model, query=self.gae_query, aggregate=self.aggregate_type)

        if aggregate_type is None:
            results = self.gae_query.Run(limit=limit, offset=start)
        elif self.aggregate_type == "count":
            return self.gae_query.Count(limit=limit, offset=start)
        else:
            raise RuntimeError("Unsupported query type")

        if self.extra_select:
            # Construct the extra_select into the results set, this is then sorted with fetchone()
            for attr, query in self.extra_select.iteritems():
                tokens = query[0].split()
                length = len(tokens)
                if length == 3:
                    op = REVERSE_OP_MAP.get(tokens[1])
                    if not op:
                        raise RuntimeError("Unsupported extra_select operation {0}".format(tokens[1]))
                    fun = FILTER_CMP_FUNCTION_MAP[op]

                    def lazy_eval(results, attr, fun, token_a, token_b):
                        """ Wraps a list or a generator, applys comparision function
                        token_a is an attribute on the result, the lhs. token_b is the rhs
                        attr is the target attribute to store the result
                        """
                        for result in results:
                            if result is None:
                                yield result

                            lhs = result.get(token_a)
                            lhs_type = type(lhs)
                            rhs = lhs_type(token_b)
                            if isinstance(rhs, basestring):
                                rhs = rhs.strip("'").strip('"') # Strip quotes
                            result[attr] = fun(lhs, rhs)
                            yield result

                    results = lazy_eval(results, attr, fun, tokens[0], tokens[2])

                elif length == 1:

                    def lazy_assign(results, attr, value):
                        """ Wraps a list or a generator, applys attribute assignment
                        """
                        for result in results:
                            if result is None:
                                yield result
                            if isinstance(value, basestring):
                                value = value.strip("'").strip('"')
                                # Horrible SQL type to python conversion attempt
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                                # Up for debate
                                # if value == "TRUE":
                                #     value = True
                                # elif value == "FALSE":
                                #     value = False
                            result[attr] = value
                            yield result

                    results = lazy_assign(results, attr, tokens[0])
                else:
                    raise RuntimeError("Unsupported extra_select")
        return results

    def next_result(self):
        while True:
            x = self.results.next()

            if isinstance(x, datastore.Key):
                if x in self.excluded_pks:
                    continue
            elif x.key() in self.excluded_pks:
                continue

            if self.distinct_on_field: #values for distinct queries
                value = x[self.distinct_on_field]
                value = self.distinct_field_convertor(value)

                if value in self.distinct_values:
                    continue
                else:
                    self.distinct_values.add(value)
                    # Insert modified value into entity before returning the entity. This is dirty,
                    # but Cursor.fetchone (which calls this) wants the entity ID and yet also wants
                    # the correct value for this field. The alternative would be to call
                    # self.distinct_field_convertor again in Cursor.fetchone, but that's wasteful.
                    x[self.distinct_on_field] = value
            return x

class FlushCommand(object):
    """
        sql_flush returns the SQL statements to flush the database,
        which are then executed by cursor.execute()

        We instead return a list of FlushCommands which are called by
        our cursor.execute
    """
    def __init__(self, table):
        self.table = table

    def execute(self):
        table = self.table
        query = datastore.Query(table, keys_only=True)
        while query.Count():
            datastore.Delete(query.Run())

        cache.clear()

class InsertCommand(object):
    def __init__(self, connection, model, objs, fields, raw):
        self.has_pk = any([x.primary_key for x in fields])
        self.entities = []
        self.included_keys = []
        self.model = model

        ancestor_field = get_ancestor_field(self.model)

        for obj in objs:
            if self.has_pk:
                #We must convert the PK value here, even though this normally happens in django_instance_to_entity otherwise
                #custom PK fields don't work properly

                #This next block creates an ancestor key, if the model has an ancestor and once was specified
                if ancestor_field and ancestor_field in [x.name for x in fields ]:
                    django_field = model._meta.get_field(ancestor_field)
                    ancestor_value = getattr(obj, django_field.attname, None)
                    if ancestor_value is not None:
                        parent = get_datastore_key(django_field.rel.to, ancestor_value)
                    else:
                        parent = None
                else:
                    parent = None

                value = model._meta.pk.get_db_prep_save(model._meta.pk.pre_save(obj, True), connection)
                self.included_keys.append(get_datastore_key(model, value, parent=parent) if value else None)
                if not self.model._meta.pk.blank and self.included_keys[-1] is None:
                    raise IntegrityError("You must specify a primary key value for {} instances".format(model))
            else:
                #We zip() self.entities and self.included_keys in execute(), so they should be the same legnth
                self.included_keys.append(None)

            self.entities.append(
                django_instance_to_entity(connection, model, fields, raw, obj)
            )

    def execute(self):
        if self.has_pk and not has_concrete_parents(self.model):
            results = []
            #We are inserting, but we specified an ID, we need to check for existence before we Put()
            #We do it in a loop so each check/put is transactional - because it's an ancestor query it shouldn't
            #cost any entity groups

            for key, ent in zip(self.included_keys, self.entities):
                @db.transactional
                def txn():
                    if key is not None:
                        if utils.key_exists(key):
                            raise IntegrityError("Tried to INSERT with existing key")

                    markers = constraints.acquire(self.model, ent)
                    try:
                        results.append(datastore.Put(ent))
                    except:
                        #Make sure we delete any created markers before we re-raise
                        constraints.release_markers(markers)
                        raise

                    entity_post_insert.send(sender=self.model, entity=ent)

                txn()

            return results
        else:
            markers = constraints.acquire_bulk(self.model, self.entities)
            try:
                results = datastore.Put(self.entities)
            except:
                to_delete = chain(*markers)
                constraints.release_markers(to_delete)
                raise

            for ent, m in zip(self.entities, markers):
                constraints.update_instance_on_markers(ent, m)
                entity_post_insert.send(sender=self.model, entity=ent)

            return results

class DeleteCommand(object):
    def __init__(self, connection, query):
        self.select = SelectCommand(connection, query)

    def execute(self):
        self.select.execute()

        #This is a little bit more inefficient than just doing a keys_only query and
        #sending it to delete, but I think this is the sacrifice to make for the unique caching layer
        keys = []
        for entity in self.select.results:
            keys.append(entity.key())
            constraints.release(self.select.model, entity)
            entity_deleted.send(sender=self.select.model, entity=entity)
        datastore.Delete(keys)

class UpdateCommand(object):
    def __init__(self, connection, query):
        self.model = query.model
        self.select = SelectCommand(connection, query, keys_only=True)
        self.values = query.values
        self.connection = connection

    @db.transactional
    def _update_entity(self, key):
        result = datastore.Get(key)
        original = copy.deepcopy(result)

        for field, param, value in self.values:
            result[field.column] = get_prepared_db_value(self.connection, MockInstance(field, value), field)

            #Add special indexed fields
            for index in special_indexes_for_column(self.model, field.column):
                indexer = REQUIRES_SPECIAL_INDEXES[index]
                result[indexer.indexed_column_name(field.column)] = indexer.prep_value_for_database(value)

        entity_pre_update.send(sender=self.model, entity=result)

        to_acquire, to_release = constraints.get_markers_for_update(self.model, original, result)

        #Acquire first, because if that fails then we don't want to alter what's already there
        constraints.acquire_identifiers(to_acquire, result.key())
        try:
            datastore.Put(result)
        except:
            constraints.release_identifiers(to_acquire)
            raise
        else:
            #Now we release the ones we don't want anymore
            constraints.release_identifiers(to_release)

        entity_post_update.send(sender=self.model, entity=result)

    def execute(self):
        self.select.execute()

        results = self.select.results

        i = 0
        for key in results:
            self._update_entity(key)
            i += 1

        return i
