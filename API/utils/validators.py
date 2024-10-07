from django.core.validators import RegexValidator
from django.utils.translation import gettext as _

mac_validator = RegexValidator("^[0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$")

alphanumeric_validator = RegexValidator(r'^[0-9a-zA-Z\,_.-]*$', _('Only alphanumeric characters are allowed.'))

alphanumeric_with_space_validator = RegexValidator(r'^[0-9a-zA-Z\, _.-]*$',
                                                   _('Only alphanumeric & Space characters are allowed.'))

numeric_validator = RegexValidator(r'^[0-9]*$', _('Only numbers are allowed.'))

