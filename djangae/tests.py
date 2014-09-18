import os
from cStringIO import StringIO
import datetime
import unittest
from string import letters
from hashlib import md5

# LIBRARIES
from django.core.files.uploadhandler import StopFutureHandlers
from django.core.cache import cache
from django.db import DataError, IntegrityError, models
from django.db.models.query import Q
from django.forms import ModelForm
from django.test import TestCase, RequestFactory
from django.forms.models import modelformset_factory
from google.appengine.api.datastore_errors import EntityNotFoundError
from django.db import connections


# DJANGAE
from djangae.db.exceptions import NotSupportedError
from djangae.db.constraints import UniqueMarker
from djangae.indexing import add_special_index
from djangae.db.utils import entity_matches_query
from djangae.db.backends.appengine.commands import normalize_query, parse_constraint
from djangae.db import transaction
from djangae.fields import ComputedCharField

from .storage import BlobstoreFileUploadHandler
from .wsgi import DjangaeApplication

from google.appengine.api import datastore

try:
    import webtest
except ImportError:
    webtest = NotImplemented

class TestUser(models.Model):
    username = models.CharField(max_length=32)
    email = models.EmailField()
    last_login = models.DateField(auto_now_add=True)
    field2 = models.CharField(max_length=32)

    def __unicode__(self):
        return self.username


class TestFruit(models.Model):
    name = models.CharField(primary_key=True, max_length=32)
    color = models.CharField(max_length=32)

class Permission(models.Model):
    user = models.ForeignKey(TestUser)
    perm = models.CharField(max_length=32)

    def __unicode__(self):
        return u"{0} for {1}".format(self.perm, self.user)

    class Meta:
        ordering = ('user__username', 'perm')


class SelfRelatedModel(models.Model):
    related = models.ForeignKey('self', blank=True, null=True)


class MultiTableParent(models.Model):
    parent_field = models.CharField(max_length=32)


class MultiTableChildOne(MultiTableParent):
    child_one_field = models.CharField(max_length=32)


class MultiTableChildTwo(MultiTableParent):
    child_two_field = models.CharField(max_length=32)


class AncestorModel(models.Model):
    name = models.CharField(max_length=32)

class DescendentModel(models.Model):
    parent = models.ForeignKey(AncestorModel, null=True, blank=True)

    class Djangae:
        ancestor_field = "parent"

class AncestorTests(TestCase):
    def test_basic_usage(self):
        parent = AncestorModel.objects.create(name="parent1")
        child1 = DescendentModel.objects.create(parent=parent)
        non_child = DescendentModel.objects.create(id=1) #Creates a child with no parent

        self.assertEqual(1, DescendentModel.objects.filter(parent=parent).count())
        self.assertEqual(child1, DescendentModel.objects.get(parent=parent))

        self.assertEqual(non_child, DescendentModel.objects.get(pk=1))

        with self.assertRaises(DescendentModel.DoesNotExist):
            DescendentModel.objects.get(pk=child1.pk) #This will throw, because no parent was specified

        DescendentModel.objects.get(parent=parent, pk=child1.pk) #This is fine, you specified the parent

        #Not an ancestor query, will just query on parent_id
        self.assertEqual(1, DescendentModel.objects.filter(parent=None).count())


class BackendTests(TestCase):
    def test_entity_matches_query(self):
        entity = datastore.Entity("test_model")
        entity["name"] = "Charlie"
        entity["age"] = 22

        query = datastore.Query("test_model")
        query["name ="] = "Charlie"
        self.assertTrue(entity_matches_query(entity, query))

        query["age >="] = 5
        self.assertTrue(entity_matches_query(entity, query))
        del query["age >="]

        query["age <"] = 22
        self.assertFalse(entity_matches_query(entity, query))
        del query["age <"]

        query["age <="] = 22
        self.assertTrue(entity_matches_query(entity, query))
        del query["age <="]

        query["name ="] = "Fred"
        self.assertFalse(entity_matches_query(entity, query))

        #If the entity has a list field, then if any of them match the
        #query then it's a match
        entity["name"] = [ "Bob", "Fred", "Dave" ]
        self.assertTrue(entity_matches_query(entity, query)) #ListField test

class ModelFormsetTest(TestCase):
    def test_reproduce_index_error(self):
        class TestModelForm(ModelForm):
            class Meta:
                model = TestUser

        test_model = TestUser.objects.create(username='foo', field2='bar')
        TestModelFormSet = modelformset_factory(TestUser, form=TestModelForm, extra=0)
        test_model_formset = TestModelFormSet(queryset=TestUser.objects.filter(pk=test_model.pk))

        data = {
            'form-INITIAL_FORMS': 0,
            'form-MAX_NUM_FORMS': 0,
            'form-TOTAL_FORMS': 0,
            'form-0-id': test_model.id,
            'form-0-field1': 'foo_1',
            'form-0-field2': 'bar_1',
        }
        factory = RequestFactory()
        request = factory.post('/', data=data)

        TestModelFormSet(request.POST, request.FILES)


class CacheTests(TestCase):

    def test_cache_set(self):
        cache.set('test?', 'yes!')
        self.assertEqual(cache.get('test?'), 'yes!')

    def test_cache_timeout(self):
        cache.set('test?', 'yes!', 1)
        import time
        time.sleep(1)
        self.assertEqual(cache.get('test?'), None)


class TransactionTests(TestCase):
    def test_atomic_decorator(self):

        @transaction.atomic
        def txn():
            TestUser.objects.create(username="foo", field2="bar")
            raise ValueError()

        with self.assertRaises(ValueError):
            txn()

        self.assertEqual(0, TestUser.objects.count())

    def test_atomic_context_manager(self):

        with self.assertRaises(ValueError):
            with transaction.atomic():
                TestUser.objects.create(username="foo", field2="bar")
                raise ValueError()

        self.assertEqual(0, TestUser.objects.count())

    def test_xg_argument(self):

        @transaction.atomic(xg=True)
        def txn(_username):
            TestUser.objects.create(username=_username, field2="bar")
            TestFruit.objects.create(name="Apple", color="pink")
            raise ValueError()

        with self.assertRaises(ValueError):
            txn("foo")

        self.assertEqual(0, TestUser.objects.count())
        self.assertEqual(0, TestFruit.objects.count())

    def test_independent_argument(self):
        """
            We would get a XG error if the inner transaction was not independent
        """

        @transaction.atomic
        def txn1(_username, _fruit):
            @transaction.atomic(independent=True)
            def txn2(_fruit):
                TestFruit.objects.create(name=_fruit, color="pink")
                raise ValueError()

            TestUser.objects.create(username=_username)
            txn2(_fruit)


        with self.assertRaises(ValueError):
            txn1("test", "banana")


class QueryNormalizationTests(TestCase):
    """
        The normalize_query function takes a Django where tree, and converts it
        into a tree of one of the following forms:

        [ (column, operator, value), (column, operator, value) ] <- AND only query
        [ [(column, operator, value)], [(column, operator, value) ]] <- OR query, of multiple ANDs
    """

    def test_and_queries(self):
        connection = connections['default']

        qs = TestUser.objects.filter(username="test").all()

        self.assertEqual(("username", "=", "test"), normalize_query(qs.query.where, connection=connection))

        qs = TestUser.objects.filter(username="test", email="test@example.com")

        expected = ('AND', [ # Cannot be reduced
            ("username", "=", "test"),
            ("email", "=", "test@example.com")
        ])
        self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))
        #
        qs = TestUser.objects.filter(username="test").exclude(email="test@example.com")

        expected = ('OR', [
            ('AND', [("username", "=", "test"), ("email", ">", "test@example.com")]),
            ('AND', [("username", "=", "test"), ("email", "<", "test@example.com")]),
        ])

        self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))

        qs = TestUser.objects.filter(username__lte="test").exclude(email="test@example.com")
        expected = ('OR', [
            ('AND', [("username", "<=", "test"), ("email", ">", "test@example.com")]),
            ('AND', [("username", "<=", "test"), ("email", "<", "test@example.com")]),
        ])

        with self.assertRaises(NotSupportedError):
            normalize_query(qs.query.where, connection=connection)

    def test_or_queries(self):

        connection = connections['default']

        qs = TestUser.objects.filter(
            username="python").filter(
            Q(username__in=["ruby", "jruby"]) | (Q(username="php") & ~Q(username="perl"))
        )

        # After IN and != explosion, we have...
        # (AND: (username='python', OR: (username='ruby', username='jruby', AND: (username='php', AND: (username < 'perl', username > 'perl')))))

        # Working backwards,
        # AND: (username < 'perl', username > 'perl') can't be simplified
        # AND: (username='php', AND: (username < 'perl', username > 'perl')) can become (OR: (AND: username = 'php', username < 'perl'), (AND: username='php', username > 'perl'))
        # OR: (username='ruby', username='jruby', (OR: (AND: username = 'php', username < 'perl'), (AND: username='php', username > 'perl')) can't be simplified
        # (AND: (username='python', OR: (username='ruby', username='jruby', (OR: (AND: username = 'php', username < 'perl'), (AND: username='php', username > 'perl'))
        # becomes...
        # (OR: (AND: username='python', username = 'ruby'), (AND: username='python', username='jruby'), (AND: username='python', username='php', username < 'perl') \
        #      (AND: username='python', username='php', username > 'perl')


        expected = ('OR', [
            ('AND', [('username', '=', 'python'), ('username', '=', 'ruby')]),
            ('AND', [('username', '=', 'python'), ('username', '=', 'jruby')]),
            ('AND', [('username', '=', 'php'), ('username', '>', 'perl'), ('username', '=', 'python')]),
            ('AND', [('username', '=', 'php'), ('username', '<', 'perl'), ('username', '=', 'python')])
        ])

        self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))
        #

        qs = TestUser.objects.filter(username="test") | TestUser.objects.filter(username="cheese")

        expected = ('OR', [
            ("username", "=", "test"),
            ("username", "=", "cheese"),
        ])

        self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))
        #
        # These tests need to be changed so they check the pk value is a key from Path
        #
        # qs = TestUser.objects.filter(pk__in=[1, 2, 3])
        #
        # expected = ('OR', [
        #     ("id", "=", 1),
        #     ("id", "=", 2),
        #     ("id", "=", 3),
        # ])
        #
        # import pdb; pdb.set_trace()
        #
        # self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))

        # qs = TestUser.objects.filter(pk__in=[1, 2, 3]).filter(username="test")
        #
        # expected = ('OR', [
        #     ('AND', [("id", "=", 1), ('username', '=', "test")]),
        #     ('AND', [("id", "=", 2), ('username', '=', "test")]),
        #     ('AND', [("id", "=", 3), ('username', '=', "test")]),
        # ])
        #
        # self.assertEqual(expected, normalize_query(qs.query.where, connection=connection))


class ModelWithUniques(models.Model):
    name = models.CharField(max_length=64, unique=True)

class ModelWithDates(models.Model):
    start = models.DateField()
    end = models.DateField()

class ConstraintTests(TestCase):
    """
        Tests for unique constaint handling
    """

    def test_update_updates_markers(self):
        initial_count = datastore.Query(UniqueMarker.kind()).Count()

        instance = ModelWithUniques.objects.create(name="One")

        self.assertEqual(1, datastore.Query(UniqueMarker.kind()).Count() - initial_count)

        qry = datastore.Query(UniqueMarker.kind())
        qry.Order(("created", datastore.Query.DESCENDING))

        marker = [ x for x in qry.Run()][0]
        self.assertEqual(datastore.Key(marker["instance"]), datastore.Key.from_path(instance._meta.db_table, instance.pk)) #Make sure we assigned the instance

        expected_marker = "{}|name:{}".format(ModelWithUniques._meta.db_table, md5("One").hexdigest())
        self.assertEqual(expected_marker, marker.key().id_or_name())

        instance.name = "Two"
        instance.save()

        self.assertEqual(1, datastore.Query(UniqueMarker.kind()).Count() - initial_count)
        marker = [ x for x in qry.Run()][0]
        self.assertEqual(datastore.Key(marker["instance"]), datastore.Key.from_path(instance._meta.db_table, instance.pk)) #Make sure we assigned the instance

        expected_marker = "{}|name:{}".format(ModelWithUniques._meta.db_table, md5("Two").hexdigest())
        self.assertEqual(expected_marker, marker.key().id_or_name())

    def test_conflicting_insert_throws_integrity_error(self):
        ModelWithUniques.objects.create(name="One")

        with self.assertRaises((IntegrityError, DataError)):
            ModelWithUniques.objects.create(name="One")

    def test_conflicting_update_throws_integrity_error(self):
        ModelWithUniques.objects.create(name="One")

        instance = ModelWithUniques.objects.create(name="Two")
        with self.assertRaises((IntegrityError, DataError)):
            instance.name = "One"
            instance.save()

    def test_error_on_update_doesnt_change_markers(self):
        initial_count = datastore.Query(UniqueMarker.kind()).Count()

        instance = ModelWithUniques.objects.create(name="One")

        self.assertEqual(1, datastore.Query(UniqueMarker.kind()).Count() - initial_count)

        qry = datastore.Query(UniqueMarker.kind())
        qry.Order(("created", datastore.Query.DESCENDING))

        marker = [ x for x in qry.Run()][0]
        self.assertEqual(datastore.Key(marker["instance"]), datastore.Key.from_path(instance._meta.db_table, instance.pk)) #Make sure we assigned the instance

        expected_marker = "{}|name:{}".format(ModelWithUniques._meta.db_table, md5("One").hexdigest())
        self.assertEqual(expected_marker, marker.key().id_or_name())

        instance.name = "Two"


        from djangae.db.backends.appengine.commands import datastore as to_patch


        try:
            original = to_patch.Put

            def func(*args, **kwargs):
                kind = args[0][0].kind() if isinstance(args[0], list) else args[0].kind()

                if kind == UniqueMarker.kind():
                    return original(*args, **kwargs)

                raise AssertionError()

            to_patch.Put = func

            with self.assertRaises(Exception):
                instance.save()
        finally:
            to_patch.Put = original

        self.assertEqual(1, datastore.Query(UniqueMarker.kind()).Count() - initial_count)
        marker = [ x for x in qry.Run()][0]
        self.assertEqual(datastore.Key(marker["instance"]), datastore.Key.from_path(instance._meta.db_table, instance.pk)) #Make sure we assigned the instance

        expected_marker = "{}|name:{}".format(ModelWithUniques._meta.db_table, md5("One").hexdigest())
        self.assertEqual(expected_marker, marker.key().id_or_name())

    def test_error_on_insert_doesnt_create_markers(self):
        initial_count = datastore.Query(UniqueMarker.kind()).Count()

        from djangae.db.backends.appengine.commands import datastore as to_patch
        try:
            original = to_patch.Put

            def func(*args, **kwargs):
                kind = args[0][0].kind() if isinstance(args[0], list) else args[0].kind()

                if kind == UniqueMarker.kind():
                    return original(*args, **kwargs)

                raise AssertionError()

            to_patch.Put = func

            with self.assertRaises(AssertionError):
                ModelWithUniques.objects.create(name="One")
        finally:
            to_patch.Put = original

        self.assertEqual(0, datastore.Query(UniqueMarker.kind()).Count() - initial_count)

    def test_delete_clears_markers(self):
        initial_count = datastore.Query(UniqueMarker.kind()).Count()

        instance = ModelWithUniques.objects.create(name="One")
        self.assertEqual(1, datastore.Query(UniqueMarker.kind()).Count() - initial_count)
        instance.delete()
        self.assertEqual(0, datastore.Query(UniqueMarker.kind()).Count() - initial_count)

class EdgeCaseTests(TestCase):
    def setUp(self):
        add_special_index(TestUser, "username", "iexact")

        self.u1 = TestUser.objects.create(username="A", email="test@example.com", last_login=datetime.datetime.now().date())
        self.u2 = TestUser.objects.create(username="B", email="test@example.com", last_login=datetime.datetime.now().date())
        TestUser.objects.create(username="C", email="test2@example.com", last_login=datetime.datetime.now().date())
        TestUser.objects.create(username="D", email="test3@example.com", last_login=datetime.datetime.now().date())
        TestUser.objects.create(username="E", email="test3@example.com", last_login=datetime.datetime.now().date())

        self.apple = TestFruit.objects.create(name="apple", color="red")
        self.banana = TestFruit.objects.create(name="banana", color="yellow")


    def test_querying_by_date(self):
        instance1 = ModelWithDates.objects.create(start=datetime.date(2014, 1, 1), end=datetime.date(2014, 1, 20))
        instance2 = ModelWithDates.objects.create(start=datetime.date(2014, 2, 1), end=datetime.date(2014, 2, 20))

        self.assertEqual(instance1, ModelWithDates.objects.get(start__lt=datetime.date(2014, 1, 2)))
        self.assertEqual(2, ModelWithDates.objects.filter(start__lt=datetime.date(2015, 1, 1)).count())

        self.assertEqual(instance2, ModelWithDates.objects.get(start__gt=datetime.date(2014, 1, 2)))
        self.assertEqual(instance2, ModelWithDates.objects.get(start__gte=datetime.date(2014, 2, 1)))


    def test_multi_table_inheritance(self):

        parent = MultiTableParent.objects.create(parent_field="parent1")
        child1 = MultiTableChildOne.objects.create(parent_field="child1", child_one_field="child1")
        child2 = MultiTableChildTwo.objects.create(parent_field="child2", child_two_field="child2")

        self.assertEqual(3, MultiTableParent.objects.count())
        self.assertItemsEqual([parent.pk, child1.pk, child2.pk],
            list(MultiTableParent.objects.values_list('pk', flat=True)))
        self.assertEqual(1, MultiTableChildOne.objects.count())
        self.assertEqual(child1, MultiTableChildOne.objects.get())

        self.assertEqual(1, MultiTableChildTwo.objects.count())
        self.assertEqual(child2, MultiTableChildTwo.objects.get())


    def test_anding_pks(self):
        results = TestUser.objects.filter(id__exact=self.u1.pk).filter(id__exact=self.u2.pk)
        self.assertEqual(list(results), [])

    def test_unusual_queries(self):

        results = TestFruit.objects.filter(name__in=["apple", "orange"])
        self.assertEqual(1, len(results))
        self.assertItemsEqual(["apple"], [x.name for x in results])

        results = TestFruit.objects.filter(name__in=["apple", "banana"])
        self.assertEqual(2, len(results))
        self.assertItemsEqual(["apple", "banana"], [x.name for x in results])

        results = TestFruit.objects.filter(name__in=["apple", "banana"]).values_list('pk', 'color')
        self.assertEqual(2, len(results))
        self.assertItemsEqual([(self.apple.pk, self.apple.color), (self.banana.pk, self.banana.color)], results)

        results = TestUser.objects.all()
        self.assertEqual(5, len(results))

        results = TestUser.objects.filter(username__in=["A", "B"])
        self.assertEqual(2, len(results))
        self.assertItemsEqual(["A", "B"], [x.username for x in results])

        results = TestUser.objects.filter(username__in=["A", "B"]).exclude(username="A")
        self.assertEqual(1, len(results), results)
        self.assertItemsEqual(["B"], [x.username for x in results])

        results = TestUser.objects.filter(username__lt="E")
        self.assertEqual(4, len(results))
        self.assertItemsEqual(["A", "B", "C", "D"], [x.username for x in results])

        results = TestUser.objects.filter(username__lte="E")
        self.assertEqual(5, len(results))

        #Double exclude on different properties not supported
        with self.assertRaises(NotSupportedError):
            list(TestUser.objects.exclude(username="E").exclude(email="A"))

        results = list(TestUser.objects.exclude(username="E").exclude(username="A"))
        self.assertItemsEqual(["B", "C", "D"], [x.username for x in results ])

        results = TestUser.objects.filter(username="A", email="test@example.com")
        self.assertEqual(1, len(results))

        results = TestUser.objects.filter(username__in=["A", "B"]).filter(username__in=["A", "B"])
        self.assertEqual(2, len(results))
        self.assertItemsEqual(["A", "B"], [x.username for x in results])

        results = TestUser.objects.filter(username__in=["A", "B"]).filter(username__in=["A"])
        self.assertEqual(1, len(results))
        self.assertItemsEqual(["A"], [x.username for x in results])

        results = TestUser.objects.filter(pk__in=[self.u1.pk, self.u2.pk]).filter(username__in=["A"])
        self.assertEqual(1, len(results))
        self.assertItemsEqual(["A"], [x.username for x in results])

        results = TestUser.objects.filter(username__in=["A"]).filter(pk__in=[self.u1.pk, self.u2.pk])
        self.assertEqual(1, len(results))
        self.assertItemsEqual(["A"], [x.username for x in results])

        results = list(TestUser.objects.all().exclude(username__in=["A"]))
        self.assertItemsEqual(["B", "C", "D", "E"], [x.username for x in results ])

    def test_or_queryset(self):
        """
            This constructs an OR query, this is currently broken in the parse_where_and_check_projection
            function. WE MUST FIX THIS!
        """
        q1 = TestUser.objects.filter(username="A")
        q2 = TestUser.objects.filter(username="B")

        self.assertItemsEqual([self.u1, self.u2], list(q1 | q2))

    def test_or_q_objects(self):
        """ Test use of Q objects in filters. """
        query = TestUser.objects.filter(Q(username="A") | Q(username="B"))
        self.assertItemsEqual([self.u1, self.u2], list(query))

    def test_extra_select(self):
        results = TestUser.objects.filter(username='A').extra(select={'is_a': "username = 'A'"})
        self.assertEqual(1, len(results))
        self.assertItemsEqual([True], [x.is_a for x in results])

        results = TestUser.objects.all().exclude(username='A').extra(select={'is_a': "username = 'A'"})
        self.assertEqual(4, len(results))
        self.assertEqual(not any([x.is_a for x in results]), True)

        # Up for debate
        # results = User.objects.all().extra(select={'truthy': 'TRUE'})
        # self.assertEqual(all([x.truthy for x in results]), True)

        results = TestUser.objects.all().extra(select={'truthy': True})
        self.assertEqual(all([x.truthy for x in results]), True)


    def test_counts(self):
        self.assertEqual(5, TestUser.objects.count())
        self.assertEqual(2, TestUser.objects.filter(email="test3@example.com").count())
        self.assertEqual(3, TestUser.objects.exclude(email="test3@example.com").count())
        self.assertEqual(1, TestUser.objects.filter(username="A").exclude(email="test3@example.com").count())
        self.assertEqual(3, TestUser.objects.exclude(username="E").exclude(username="A").count())

    def test_deletion(self):
        count = TestUser.objects.count()

        self.assertTrue(count)

        TestUser.objects.filter(username="A").delete()

        self.assertEqual(count - 1, TestUser.objects.count())

        TestUser.objects.filter(username="B").exclude(username="B").delete() #Should do nothing

        self.assertEqual(count - 1, TestUser.objects.count())

        TestUser.objects.all().delete()

        count = TestUser.objects.count()

        self.assertFalse(count)

    def test_insert_with_existing_key(self):
        user = TestUser.objects.create(id=1, username="test1", last_login=datetime.datetime.now().date())
        self.assertEqual(1, user.pk)

        with self.assertRaises(IntegrityError):
            TestUser.objects.create(id=1, username="test2", last_login=datetime.datetime.now().date())

    def test_included_pks(self):
        ids = [ TestUser.objects.get(username="B").pk, TestUser.objects.get(username="A").pk ]
        results = TestUser.objects.filter(pk__in=ids).order_by("username")

        self.assertEqual(results[0], self.u1)
        self.assertEqual(results[1], self.u2)

    def test_select_related(self):
        """ select_related should be a no-op... for now """
        user = TestUser.objects.get(username="A")
        perm = Permission.objects.create(user=user, perm="test_perm")
        select_related = [ (p.perm, p.user.username) for p in user.permission_set.select_related() ]
        self.assertEqual(user.username, select_related[0][1])

    def test_cross_selects(self):
        user = TestUser.objects.get(username="A")
        perm = Permission.objects.create(user=user, perm="test_perm")
        with self.assertRaises(NotSupportedError):
            perms = list(Permission.objects.all().values_list("user__username", "perm"))
            self.assertEqual("A", perms[0][0])

    def test_values_list_on_pk_does_keys_only_query(self):
        from google.appengine.api.datastore import Query

        def replacement_init(*args, **kwargs):
            replacement_init.called_args = args
            replacement_init.called_kwargs = kwargs
            original_init(*args, **kwargs)

        replacement_init.called_args = None
        replacement_init.called_kwargs = None

        try:
            original_init = Query.__init__
            Query.__init__ = replacement_init
            list(TestUser.objects.all().values_list('pk', flat=True))
        finally:
            Query.__init__ = original_init

        self.assertTrue(replacement_init.called_kwargs.get('keys_only'))
        self.assertEqual(5, len(TestUser.objects.all().values_list('pk')))

    def test_iexact(self):
        user = TestUser.objects.get(username__iexact="a")
        self.assertEqual("A", user.username)

    def test_ordering(self):
        users = TestUser.objects.all().order_by("username")

        self.assertEqual(["A", "B", "C", "D", "E"], [x.username for x in users])

        users = TestUser.objects.all().order_by("-username")

        self.assertEqual(["A", "B", "C", "D", "E"][::-1], [x.username for x in users])

    def test_dates_query(self):
        z_user = TestUser.objects.create(username="Z", email="z@example.com")
        z_user.last_login = datetime.date(2013, 4, 5)
        z_user.save()

        last_a_login = TestUser.objects.get(username="A").last_login

        dates = TestUser.objects.dates('last_login', 'year')

        self.assertItemsEqual(
            [datetime.date(2013, 1, 1), datetime.date(last_a_login.year, 1, 1)],
            dates
        )

        dates = TestUser.objects.dates('last_login', 'month')
        self.assertItemsEqual(
            [datetime.date(2013, 4, 1), datetime.date(last_a_login.year, last_a_login.month, 1)],
            dates
        )

        dates = TestUser.objects.dates('last_login', 'day')
        self.assertItemsEqual(
            [datetime.date(2013, 4, 5), last_a_login],
            dates
        )

        dates = TestUser.objects.dates('last_login', 'day', order='DESC')
        self.assertItemsEqual(
            [last_a_login, datetime.date(2013, 4, 5)],
            dates
        )

    def test_in_query(self):
        """ Test that the __in filter works, and that it cannot be used with more than 30 values,
            unless it's used on the PK field.
        """
        # Check that a basic __in query works
        results = list(TestUser.objects.filter(username__in=['A', 'B']))
        self.assertItemsEqual(results, [self.u1, self.u2])
        # Check that it also works on PKs
        results = list(TestUser.objects.filter(pk__in=[self.u1.pk, self.u2.pk]))
        self.assertItemsEqual(results, [self.u1, self.u2])
        # Check that using more than 30 items in an __in query not on the pk causes death
        query = TestUser.objects.filter(username__in=list([x for x in letters[:31]]))
        # This currently rasies an error from App Engine, should we raise our own?
        self.assertRaises(Exception, list, query)
        # Check that it's ok with PKs though
        query = TestUser.objects.filter(pk__in=list(xrange(1, 32)))
        list(query)

    def test_self_relations(self):
        obj = SelfRelatedModel.objects.create()
        obj2 = SelfRelatedModel.objects.create(related=obj)
        self.assertEqual(list(obj.selfrelatedmodel_set.all()), [obj2])


class BlobstoreFileUploadHandlerTest(TestCase):
    boundary = "===============7417945581544019063=="

    def setUp(self):
        self.request = RequestFactory().get('/')
        self.request.META = {
            'wsgi.input': self._create_wsgi_input(),
            'content-type': 'message/external-body; blob-key="PLOF0qOie14jzHWJXEa9HA=="; access-type="X-AppEngine-BlobKey"'
        }
        self.uploader = BlobstoreFileUploadHandler(self.request)

    def _create_wsgi_input(self):
        return StringIO('--===============7417945581544019063==\r\nContent-Type:'
                        ' text/plain\r\nContent-Disposition: form-data;'
                        ' name="field-nationality"\r\n\r\nAS\r\n'
                        '--===============7417945581544019063==\r\nContent-Type:'
                        ' message/external-body; blob-key="PLOF0qOie14jzHWJXEa9HA==";'
                        ' access-type="X-AppEngine-BlobKey"\r\nContent-Disposition:'
                        ' form-data; name="field-file";'
                        ' filename="Scan.tiff"\r\n\r\nContent-Type: image/tiff'
                        '\r\nContent-Length: 19837164\r\nContent-MD5:'
                        ' YjI1M2Q5NjM5YzdlMzUxYjMyMjA0ZTIxZjAyNzdiM2Q=\r\ncontent-disposition:'
                        ' form-data; name="field-file";'
                        ' filename="Scan.tiff"\r\nX-AppEngine-Upload-Creation: 2014-03-07'
                        ' 14:48:03.246607\r\n\r\n\r\n'
                        '--===============7417945581544019063==\r\nContent-Type:'
                        ' text/plain\r\nContent-Disposition: form-data;'
                        ' name="field-number"\r\n\r\n6\r\n'
                        '--===============7417945581544019063==\r\nContent-Type:'
                        ' text/plain\r\nContent-Disposition: form-data;'
                        ' name="field-salutation"\r\n\r\nmrs\r\n'
                        '--===============7417945581544019063==--')

    def test_non_existing_files_do_not_get_created(self):
        file_field_name = 'field-file'
        length = len(self._create_wsgi_input().read())
        self.uploader.handle_raw_input(self.request.META['wsgi.input'], self.request.META, length, self.boundary, "utf-8")
        self.assertRaises(StopFutureHandlers, self.uploader.new_file, file_field_name, 'file_name', None, None)
        self.assertRaises(EntityNotFoundError, self.uploader.file_complete, None)

    def test_blob_key_creation(self):
        file_field_name = 'field-file'
        length = len(self._create_wsgi_input().read())
        self.uploader.handle_raw_input(self.request.META['wsgi.input'], self.request.META, length, self.boundary, "utf-8")
        self.assertRaises(
            StopFutureHandlers,
            self.uploader.new_file, file_field_name, 'file_name', None, None
        )
        self.assertIsNotNone(self.uploader.blobkey)

class ApplicationTests(TestCase):

    @unittest.skipIf(webtest is NotImplemented, "pip install webtest to run functional tests")
    def test_environ_is_patched_when_request_processed(self):
        def application(environ, start_response):
            # As we're not going through a thread pool the environ is unset.
            # Set it up manually here.
            # TODO: Find a way to get it to be auto-set by webtest
            from google.appengine.runtime import request_environment
            request_environment.current_request.environ = environ

            # Check if the os.environ is the same as what we expect from our
            # wsgi environ
            import os
            self.assertEqual(environ, os.environ)
            start_response("200 OK", [])
            return ["OK"]

        djangae_app = DjangaeApplication(application)
        test_app = webtest.TestApp(djangae_app)
        old_environ = os.environ
        try:
            test_app.get("/")
        finally:
            os.environ = old_environ


class ComputedFieldModel(models.Model):
    def computer(self):
        return "%s_%s" % (self.int_field, self.char_field)

    int_field = models.IntegerField()
    char_field = models.CharField(max_length=50)
    test_field = ComputedCharField(computer, max_length=50)


class ComputedFieldTests(TestCase):
    def test_computed_field(self):
        instance = ComputedFieldModel(int_field=1, char_field="test")
        instance.save()
        self.assertEqual(instance.test_field, "1_test")
