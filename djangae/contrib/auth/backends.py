from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured

from djangae.contrib.auth.models import GaeAbstractUser
from django.contrib.auth.backends import ModelBackend

class AppEngineUserAPI(ModelBackend):
    """
        A custom Django authentication backend, which lets us authenticate against the Google
        users API
    """

    supports_anonymous_user = True

    def authenticate(self, **credentials):
        """
        Handles authentication of a user from the given credentials.
        Credentials must be a combination of 'request' and 'google_user'.
         If any other combination of credentials are given then we raise a TypeError, see authenticate() in django.contrib.auth.__init__.py.
        """

        User = get_user_model()

        if not issubclass(User, GaeAbstractUser):
            raise ImproperlyConfigured("You cannot user the AppEngineUserAPI with this User model.")

        if len(credentials) != 2:
            raise TypeError()

        request = credentials.get('request', None)
        google_user = credentials.get('google_user', None)

        if request and google_user:
            user_id = google_user.user_id()
            email = google_user.email().lower()
            try:
                user = User.objects.get(user_id=user_id)

            except User.DoesNotExist:
                user = User.objects.create_user(user_id, email)

            return user
        else:
            raise TypeError()  # Django expects to be able to pass in whatever credentials it has, and for you to raise a TypeError if they mean nothing to you
