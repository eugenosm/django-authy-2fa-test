from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, email, authy_id, password, is_superuser):
        if not username:
            raise ValueError('Username must be set')
        username = self.model.normalize_username(username)
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, authy_id=authy_id, is_superuser=is_superuser)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, authy_id=None, password=None):
        return self._create_user(username, email, authy_id, password, is_superuser=False)

    def create_superuser(self, username, email, authy_id, password, **kwargs):
        return self._create_user(username, email, authy_id, password, is_superuser=True)
