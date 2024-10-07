from django.contrib.postgres.fields import JSONField
from django.db import models, transaction
from django.utils.translation import gettext as _

from report_app.models import Notification


class Policy(models.Model):
    ACTION_CHOICE = (
        ('accept', 'accept'),
        ('reject', 'reject'),
        ('drop', 'drop')
    )
    action = models.CharField(_('Action'), max_length=6, null=True, blank=True)
    next_policy = models.ForeignKey('Policy', on_delete=models.SET_NULL, related_name='+', null=True, blank=True)

    name = models.CharField(_('Name'), max_length=15, unique=True)
    description = models.TextField(_('Description'), null=True, blank=True)

    schedule = models.ForeignKey('entity_app.Schedule', verbose_name=_('Schedule'), on_delete=models.CASCADE,
                                 null=True, blank=True)

    is_enabled = models.BooleanField(_('Is Enabled'), default=True)
    is_log_enabled = models.BooleanField(_('Is Log Enabled'), default=True)

    source_destination = models.ForeignKey('SourceDestination', verbose_name=_('Source_Destination'),
                                           on_delete=models.CASCADE, null=True, blank=True)
    nat = models.ForeignKey('NAT', verbose_name=_('NAT'), on_delete=models.CASCADE, null=True, blank=True)
    pbr = models.ForeignKey('PBR', verbose_name=_('PBR'), on_delete=models.CASCADE, null=True, blank=True)
    qos = models.ForeignKey('QOS', verbose_name=_('QOS'), on_delete=models.CASCADE, null=True, blank=True)

    is_ipsec = models.BooleanField(_('Is Ipsec'), default=False)

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('delete', 'delete'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    class Meta:
        verbose_name = _('Policy')
        verbose_name_plural = _('Policies')

    def save(self, *args, **kwargs):
        is_update = False
        before_update = None

        if self.pk:
            before_update = Policy.objects.get(id=self.id)
            is_update = True

        with transaction.atomic():
            super(Policy, self).save(*args, **kwargs)

            if is_update:
                try:
                    old_previous_policy = Policy.objects.get(next_policy=self)
                    old_previous_policy.next_policy = before_update.next_policy
                    super(Policy, old_previous_policy).save()

                except Policy.DoesNotExist:
                    pass

            if self.next_policy:
                try:
                    previous_policy = Policy.objects.exclude(id=self.id).get(next_policy=self.next_policy)
                    previous_policy.next_policy = self
                    super(Policy, previous_policy).save()

                except Policy.DoesNotExist:
                    pass

            else:
                try:
                    last_policy = Policy.objects.exclude(id=self.id).get(next_policy__isnull=True)
                    last_policy.next_policy = self
                    super(Policy, last_policy).save()

                except Policy.DoesNotExist:
                    pass

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            try:
                previous_policy = Policy.objects.get(next_policy=self)
                previous_policy.next_policy = self.next_policy
                super(Policy, previous_policy).save()

            except Policy.DoesNotExist:
                pass

            if hasattr(self, 'nat') and self.nat:
                self.nat.delete()
            if hasattr(self, 'qos') and self.qos:
                self.qos.delete()

            if self.pbr:
                self.pbr.delete()

            self.source_destination.delete()

            Notification.objects.filter(source='policy', item__id=self.id).delete()

            super(Policy, self).delete(*kwargs, **kwargs)

    def __str__(self):
        return str(self.id)


class SourceDestination(models.Model):
    # user_list = models.ManyToManyField()
    # group_list = models.ManyToManyField()

    src_interface_list = models.ManyToManyField('config_app.Interface', blank=True, related_name='+')
    dst_interface_list = models.ManyToManyField('config_app.Interface', blank=True, related_name='+')

    src_network_list = models.ManyToManyField('entity_app.Address', blank=True, related_name='+')
    dst_network_list = models.ManyToManyField('entity_app.Address', blank=True, related_name='+')

    service_list = models.ManyToManyField('entity_app.Service', blank=True, related_name='+')
    # application_list = models.ManyToManyField('entity_app.Application', blank=True, related_name='+')

    src_geoip_country_list = models.ManyToManyField('entity_app.CountryCode', blank=True, related_name='+')
    dst_geoip_country_list = models.ManyToManyField('entity_app.CountryCode', blank=True, related_name='+')


class NAT(models.Model):
    name = models.CharField(_('Name'), max_length=20, null=True, blank=True)
    description = models.TextField(_('Description'), max_length=80, null=True, blank=True)
    next_policy = models.ForeignKey('NAT', on_delete=models.SET_NULL, related_name='+', null=True, blank=True)

    NAT_TYPE_CHOICES = (
        ('SNAT', 'SNAT'),
        ('DNAT', 'DNAT')
    )
    nat_type = models.CharField(_("NAT Type"), choices=NAT_TYPE_CHOICES, max_length=4)

    SNAT_TYPE_CHOICES = (
        ('interface_ip', 'Interface IP'),
        ('static_ip', 'Static IP')
    )
    snat_type = models.CharField(_("SNAT Type"), choices=SNAT_TYPE_CHOICES, max_length=15, blank=True, null=True)

    ip = models.GenericIPAddressField(_("IP Address"), blank=True, null=True)
    port = models.CharField(_("Port"), blank=True, null=True, max_length=10)

    is_enabled = models.BooleanField(_('Is Enabled'), default=True)
    is_connected_to_policy = models.BooleanField(_('Is Connected to Policy'), default=False)

    source_destination = models.ForeignKey('SourceDestination', verbose_name=_('Source_Destination'),
                                           on_delete=models.CASCADE)
    schedule = models.ForeignKey('entity_app.Schedule', verbose_name=_('Schedule'), on_delete=models.CASCADE,
                                 null=True, blank=True)

    def __str__(self):
        if self.nat_type:
            if self.snat_type:
                return self.nat_type + ' ' + self.snat_type
            return self.nat_type


class PBR(models.Model):
    source_destination = models.ForeignKey('SourceDestination', verbose_name=_('Source_Destination'),
                                           on_delete=models.CASCADE)
    is_enabled = models.BooleanField(_('Is Enabled'), default=True)
    is_connected_to_policy = models.BooleanField(_('Is Connected to Policy'), default=False)


class PolicyCommandsForTest(models.Model):
    create_chains = JSONField(_('chain_commands'), null=True, blank=True)
    chain_commands = JSONField(_('chain_commands'), null=True, blank=True)
    main_rule_commands = JSONField(_('chain_commands'), null=True, blank=True)
    nat_rule_commands = JSONField(_('chain_commands'), null=True, blank=True)
    pbr_commands = JSONField(_('chain_commands'), null=True, blank=True)
    src_ip_list = JSONField(_('src_ip_list'), null=True, blank=True)
    dst_ip_list = JSONField(_('dst_ip_list'), null=True, blank=True)
    main_order = models.IntegerField(null=True, default=0)
    nat_order = models.IntegerField(null=True, default=0)
    policy_id = models.IntegerField(null=False, unique=True)


class QOS(models.Model):
    # is_enabled = models.BooleanField(_('Is Enabled'), default=True)
    download_max_bw = models.PositiveIntegerField(_('Max_bandwidth'), blank=True, null=True)
    download_guaranteed_bw = models.PositiveIntegerField(_('Guaranteed_bandwidth'), blank=True, null=True)
    PRIORITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    )
    traffic_priority = models.CharField(_('Priority'), max_length=20, choices=PRIORITY_CHOICES, default='medium')
    TYPE_CHOICES = (
        ('per_ip', 'Per_IP'),
        ('per_session', 'Per_Session')
    )
    shape_type = models.CharField(_('Type'), max_length=20, choices=TYPE_CHOICES, default='per_session')
    class_id = models.PositiveIntegerField(_('class_id'), blank=True, null=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)
