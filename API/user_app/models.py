from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext as _

from utils.validators import alphanumeric_validator, alphanumeric_with_space_validator, numeric_validator


class User(models.Model):
    username = models.CharField(_('Username'), max_length=50, unique=True, validators=[alphanumeric_validator])

    AUTH_CHOICES = (
        ('pass', 'Password'),
        ('mac', 'MAC Auth'),
        ('ip', 'IP Auth'),
        ('cert', 'Certificate'),
        ('OTP', 'Others')
    )

    # ????????default???
    auth_type = models.CharField(_('Authentication type'), max_length=5, default=None, null=True,
                                 blank=True, choices=AUTH_CHOICES)

    password = models.CharField(_('Password'), max_length=100, default=None, blank=True, null=True)
    mac = models.ManyToManyField('UserMac', verbose_name=_('MAC Authentic'), related_name='clients', blank=True)
    ip = models.GenericIPAddressField(_('IP Authentic'), default=None, blank=True, null=True)
    cert = models.ForeignKey('Certificate', default=None, blank=True, null=True, on_delete=models.CASCADE)

    full_name = models.CharField(_('Fullname'), max_length=100, default=None, null=True, blank=True,
                                 validators=[alphanumeric_with_space_validator])
    email = models.EmailField(_('Email'), default=None, blank=True, null=True, max_length=254)

    groups = models.ManyToManyField('Group', through='Membership', verbose_name=_('groups'),
                                    related_name='clients', blank=True)

    quota = models.ForeignKey('Accounting', default=None, blank=True, null=True, related_name='user_quota',
                              on_delete=models.CASCADE)

    # QOS
    access_time = models.ForeignKey('AccessTime', verbose_name=_('Access Time'), default=None, blank=True,
                                    null=True, related_name='user_access_time', on_delete=models.CASCADE)
    force_logout = models.BooleanField(_('Apply changes immediately'), default=False, blank=True,
                                       help_text='Logged out users immediatly')

    # ????????????
    # zone = models.ManyToManyField(object_zone, blank=True)

    IP_binding = models.CharField(_('IP binding'), max_length=500, default=None, blank=True, null=True)
    MAC_binding = models.CharField(_('MAC binding'), max_length=500, default=None, blank=True, null=True)

    ## keeps the status of users objetcs (applied=1,unapplied=0,...)
    status = models.IntegerField(default=0, blank=True, null=True)
    add_update_status = models.CharField(default='add', blank=True, null=True, max_length=100)

    # ????????????
    # wan_interface = models.ForeignKey(interface_configuration, null=True, blank=True)
    def __str__(self):
        return self.username

    class Meta:
        verbose_name = _('Client')
        verbose_name_plural = _('Clients')


class Group(models.Model):
    name = models.CharField(_('Name'), max_length=50, null=False, blank=False, unique=True,
                            validators=[alphanumeric_validator])
    quota = models.ForeignKey('Accounting', blank=True, null=True, related_name='group_quota', on_delete=models.CASCADE)

    permission = models.ForeignKey('ProfilePermission', blank=True, null=True, on_delete=models.CASCADE)
    access_time = models.ForeignKey('AccessTime', blank=True, null=True, related_name='group_access_time',
                                    on_delete=models.CASCADE)
    force_logout_group = models.NullBooleanField(_('Apply changes immediately'), default=False, blank=True,
                                                 help_text='Logged out users immediatly')
    # ??????????
    # zone = models.ManyToManyField(object_zone, blank=True)

    ## keeps the status of groups objetcs (applied=1,unapplied=0,...)
    status = models.IntegerField(default=0, blank=True, null=True)

    # ??????????
    # wan_interface = models.ForeignKey(interface_configuration, null=True, blank=True)

    def __unicode__(self):
        return u'%s' % self.name

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _('Group')
        verbose_name_plural = _('Groups')


class Membership(models.Model):
    user = models.ForeignKey('User', related_name='user_id', blank=False, null=False, default=None,
                             on_delete=models.CASCADE)
    group = models.ForeignKey('Group', related_name='group_id', blank=False, null=False, default=None,
                              on_delete=models.CASCADE)
    priority = models.PositiveIntegerField(_('Priority'), null=False, blank=False, validators=[
        RegexValidator(regex='^[1-9]\d*$', message=_('Enter a positive number from 1 to any'))])

    def __unicode__(self):
        return u'%s members of %s with priority of %s' % (self.user.username, self.group.name, self.priority)

    class Meta:
        verbose_name = _('Membership')
        verbose_name_plural = _('Memberships')


class UserMac(models.Model):
    user = models.ForeignKey('User', related_name='user_id_mac', on_delete=models.CASCADE)
    mac = models.CharField(verbose_name=_('MAC'), max_length=100, default=None, blank=True, null=False, unique=True)
    force_mac_auth = models.BooleanField(_('MAC binding'), default=False, blank=True)

    def __unicode__(self):
        return u'%s' % (self.mac)

    def __str__(self):
        return self.mac

    class Meta:
        verbose_name = _('User Mac')
        verbose_name_plural = _('Users Mac')


class Certificate(models.Model):
    name = models.CharField(_('Name'), max_length=50, validators=[alphanumeric_validator])
    issuing_time = models.DateField(_('Issuing time'), default=None)
    expire_time = models.DateField(_('Expire time'), default=None)
    key_length = models.IntegerField(_('Key length'), default=None)  # 4 byte
    cert_id = models.CharField(_('Certificate ID'), max_length=20)
    country = models.CharField(_('Country'), max_length=100)
    state = models.CharField(_('State'), max_length=100)
    locality = models.CharField(_('Locality'), max_length=100)
    organization = models.CharField(_('Organization'), max_length=100)
    organization_unit_name = models.CharField(_('Organization unit name'), max_length=100)
    common_name = models.CharField(_('Common name'), max_length=100)
    email = models.EmailField(_('Email'), default=None)
    format = models.CharField(_('Format'), max_length=20)
    uploaded_file = models.FileField(_('Certificate file'), null=True,
                                     blank=True)  # upload_to= '?' where to put users certificates!

    def __unicode__(self):
        return u'%s' % self.name

    class Meta:
        verbose_name = _('Certificate')
        verbose_name_plural = _('Certificates')


# profile accounting : each user/group has an accounting info for authorizing
class Accounting(models.Model):
    name = models.CharField(_('Name'), max_length=200, unique=True, validators=[alphanumeric_validator])
    description = models.TextField(_('Description'), max_length=500, blank=True)
    status = models.IntegerField(_('Status'), default=0, blank=True)

    QUOTA_UNIT_CHOICES = (
        ('KB', 'KiloByte'),
        ('MB', 'MegaByte')
    )
    # Day
    quota_daily_download = models.PositiveIntegerField(_('Quota daily download'), default=None, blank=True, null=True)
    daily_unit_download = models.CharField(_('Daily unit download'), choices=QUOTA_UNIT_CHOICES, max_length=2,
                                           default='MB')
    quota_daily_upload = models.PositiveIntegerField(_('Quota daily upload'), default=None, blank=True, null=True)
    daily_unit_upload = models.CharField(_('Daily unit upload'), choices=QUOTA_UNIT_CHOICES, max_length=2, default='MB')

    # week
    quota_weekly_download = models.PositiveIntegerField(_('Quota weekly download'), default=None, blank=True, null=True)
    weekly_unit_download = models.CharField(_('Weekly unit download'), choices=QUOTA_UNIT_CHOICES, max_length=2,
                                            default='MB')
    quota_weekly_upload = models.PositiveIntegerField(_('Quota weekly upload'), default=None, blank=True, null=True)
    weekly_unit_upload = models.CharField(_('Weekly unit upload'), choices=QUOTA_UNIT_CHOICES, max_length=2,
                                          default='MB')

    # month
    quota_monthly_download = models.PositiveIntegerField(_('Quota monthly download'), default=None, blank=True,
                                                         null=True)
    monthly_unit_download = models.CharField(_('Monthly unit download'), choices=QUOTA_UNIT_CHOICES, max_length=2,
                                             default='MB')
    quota_monthly_upload = models.PositiveIntegerField(_('Quota monthly upload'), default=None, blank=True, null=True)
    monthly_unit_upload = models.CharField(_('Monthly unit upload'), choices=QUOTA_UNIT_CHOICES, max_length=2,
                                           default='MB')

    exceeded_quota_active = models.BooleanField(_('Active Exceeded Quota'), default=False, blank=True,
                                                help_text='Active Exceeded Quota')
    exceeded_quota = models.CharField(_('Download Bandwidth (kbit/s)'), max_length=3, default=None, null=True,
                                      blank=True, validators=[numeric_validator])
    exceeded_quota_upload = models.CharField(_('Upload Bandwidth (kbit/s)'), max_length=3, default=None, null=True,
                                             blank=True, validators=[numeric_validator])

    # notify users by email when their quota exceded
    notification_enabled = models.BooleanField(_('Notify User,Group(s)'), blank=True, default=False)
    summary = models.TextField(_('Summary'), max_length=500, blank=True, null=True)

    def __unicode__(self):
        return u'%s' % self.name

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _('Quota')
        verbose_name_plural = _('Quotas')


# profile accounting : each user/group when(Year/Month/Day:Hours) to access network
class AccessTime(models.Model):
    name = models.CharField(_('Name'), max_length=200, unique=True, blank=False, validators=[alphanumeric_validator])
    status = models.IntegerField(_('Status'), default=0, blank=True)
    # set the YYYY-MM-DD for the profile
    # set the exact time (HH:MM) for the profile
    sat_start_access_time = models.TimeField(_('Saturday start time'), default=None, blank=True, null=True)
    sat_end_access_time = models.TimeField(_('Saturday end time'), default=None, blank=True, null=True)

    sun_start_access_time = models.TimeField(_('Sunday start time'), default=None, blank=True, null=True)
    sun_end_access_time = models.TimeField(_('Sunday end time'), default=None, blank=True, null=True)

    mon_start_access_time = models.TimeField(_('Monday start time'), default=None, blank=True, null=True)
    mon_end_access_time = models.TimeField(_('Monday end time'), default=None, blank=True, null=True)

    tue_start_access_time = models.TimeField(_('Tuesday start time'), default=None, blank=True, null=True)
    tue_end_access_time = models.TimeField(_('Tuesday end time'), default=None, blank=True, null=True)

    wed_start_access_time = models.TimeField(_('Wednsday start time'), default=None, blank=True, null=True)
    wed_end_access_time = models.TimeField(_('Wednsday end time'), default=None, blank=True, null=True)

    thu_start_access_time = models.TimeField(_('Thursday start time'), default=None, blank=True, null=True)
    thu_end_access_time = models.TimeField(_('Thursday end time'), default=None, blank=True, null=True)

    fri_start_access_time = models.TimeField(_('Friday start time'), default=None, blank=True, null=True)
    fri_end_access_time = models.TimeField(_('Friday end time'), default=None, blank=True, null=True)

    #    profile_access_enabled :
    #  True: access type : Access
    #  False : access type : Deny
    profile_access_enabled = models.BooleanField(_('Access status'), default=False, blank=True)

    def __unicode__(self):
        return u'%s' % self.name

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _('Access Time')
        verbose_name_plural = _('Access Times')


class ProfilePermissionName(models.Model):
    name = models.CharField(max_length=200)

    def __unicode__(self):
        return u'%s' % self.name or u''


class ProfilePermissionModule(models.Model):
    module = models.CharField(max_length=100)

    def __unicode__(self):
        return u'%s' % self.module or u''


class AccessRight(models.Model):
    access_right = models.CharField(max_length=20, default=None)

    def __unicode__(self):
        return u'%s' % self.access_right or u''


class ProfilePermission(models.Model):
    profile_name = models.ForeignKey('ProfilePermissionName', on_delete=models.CASCADE, null=False)
    profile_module_name = models.ForeignKey('ProfilePermissionModule', on_delete=models.CASCADE, null=False)

    access_rights = models.ManyToManyField('AccessRight', related_name='profiles', blank=False, default=None)

    def __unicode__(self):
        return u'%s' % self.profile_name

    def __str__(self):
        return self.profile_name

    class Meta:
        verbose_name = _('Permission')
        verbose_name_plural = _('Permissions')
