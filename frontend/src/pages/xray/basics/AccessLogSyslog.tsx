import { Alert, Input, InputNumber, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';

import { SettingListItem } from '@/components/ui';
import type { AccessLogSyslogConfig } from '@/schemas/xray';
import { onNumber } from '@/utils/onNumber';

interface Props {
  value: AccessLogSyslogConfig;
  onChange: (value: AccessLogSyslogConfig) => void;
  restartRequired: boolean;
  localLogEnabled: boolean;
}

export default function AccessLogSyslog({
  value,
  onChange,
  restartRequired,
  localLogEnabled,
}: Props) {
  const { t } = useTranslation();
  const update = (patch: Partial<AccessLogSyslogConfig>) => onChange({ ...value, ...patch });
  return (
    <>
      <SettingListItem
        title={t('pages.xray.syslog.enable')}
        description={t('pages.xray.syslog.desc')}
        paddings="small"
        control={
          <Switch
            aria-label={t('pages.xray.syslog.enable')}
            checked={value.enabled}
            onChange={(enabled) => update({ enabled })}
          />
        }
      />
      {restartRequired && (
        <Alert
          className="mb-12 hint-alert"
          type="warning"
          showIcon
          title={t('pages.xray.syslog.restart')}
        />
      )}
      {value.enabled && (
        <>
          {!localLogEnabled && (
            <Alert
              className="mb-12 hint-alert"
              type="error"
              showIcon
              title={t('pages.xray.syslog.localLogRequired')}
            />
          )}
          <SettingListItem
            title={t('pages.xray.syslog.protocol')}
            paddings="small"
            control={
              <Select
                aria-label={t('pages.xray.syslog.protocol')}
                value={value.protocol}
                style={{ width: '100%' }}
                options={[
                  { value: 'udp', label: 'UDP' },
                  { value: 'tcp', label: 'TCP' },
                ]}
                onChange={(protocol) => update({ protocol })}
              />
            }
          />
          <SettingListItem
            title={t('pages.xray.syslog.host')}
            description={t('pages.xray.syslog.hostDesc')}
            paddings="small"
            control={
              <Input
                aria-label={t('pages.xray.syslog.host')}
                value={value.host}
                placeholder="syslog.example.com"
                onChange={(event) => update({ host: event.target.value })}
              />
            }
          />
          <SettingListItem
            title={t('pages.xray.syslog.port')}
            paddings="small"
            control={
              <InputNumber
                aria-label={t('pages.xray.syslog.port')}
                value={value.port || undefined}
                min={1}
                max={65535}
                style={{ width: '100%' }}
                onChange={onNumber((port) => update({ port }))}
              />
            }
          />
        </>
      )}
    </>
  );
}
