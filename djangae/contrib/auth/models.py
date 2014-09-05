import re

from django.contrib import auth
from django.contrib.auth.models import (
    AbstractBaseUser,
    Permission,
    python_2_unicode_compatible,
    GroupManager,
    BaseUserManager,
    _user_get_all_permissions,
    _user_has_perm,
    _user_has_module_perms,
    urlquote,
)
from django.core.mail import send_mail
from django.core import validators
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from djangae.fields import ListField



@python_2_unicode_compatible
class Group(models.Model):
    """
        This is a clone of django.contrib.auth.Group, but nonrelationalized. Doesn't user Permission but directly
        uses the permission names
    """
    name = models.CharField(_('name'), max_length=80, unique=True)
    permissions = ListField(models.CharField(max_length=500),
        verbose_name=_('permissions'), blank=True)

    objects = GroupManager()

    class Meta:
        verbose_name = _('group')
        verbose_name_plural = _('groups')
        app_label = "djangae"

    def __str__(self):
        return self.name

    def natural_key(self):
        return (self.name,)

class PermissionsMixin(models.Model):
    """
    A mixin class that adds the fields and methods necessary to support
    Django's Group and Permission model using the ModelBackend.
    """
    is_superuser = models.BooleanField(_('superuser status'), default=False,
        help_text=_('Designates that this user has all permissions without '
                    'explicitly assigning them.'))
    groups = ListField(models.ForeignKey(Group), verbose_name=_('groups'),
        blank=True, help_text=_('The groups this user belongs to. A user will '
                                'get all permissions granted to each of '
                                'his/her group.'))
    user_permissions = ListField(models.ForeignKey(Permission),
        verbose_name=_('user permissions'), blank=True,
        help_text='Specific permissions for this user.')

    class Meta:
        abstract = True

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through his/her
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                if obj is not None:
                    permissions.update(backend.get_group_permissions(self,
                                                                     obj))
                else:
                    permissions.update(backend.get_group_permissions(self))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)


class UserManager(BaseUserManager):
    # TODO: do we need this?  Or does it all get taken care of when we specify USERNAME?
    pass


class GaeAbstractUser(AbstractBaseUser):
    """ Absract base class for creating a User model which works with the App Engine users API. """

    user_id = models.CharField(
        _('User ID'), max_length=21, unique=True,
        validators=[
            validators.RegexValidator(re.compile('^\d{21}$'), _('User Id should be 21 digits.'), 'invalid')
        ]
    )
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)
    email = models.EmailField(_('email address'))
    is_staff = models.BooleanField(
        _('staff status'), default=False,
        help_text=_('Designates whether the user can log into this admin site.')
    )
    is_active = models.BooleanField(
        _('active'), default=True,
        help_text=_(
            'Designates whether this user should be treated as '
            'active. Unselect this instead of deleting accounts.'
        )
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'user_id'
    REQUIRED_FIELDS = ['email']

    class Meta:
        absract = True
        verbose_name = _('user')
        verbose_name_plural = _('users')
        app_label = "djangae"

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.user_id)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])


class User(GaeAbstractUser, PermissionsMixin):
    pass
