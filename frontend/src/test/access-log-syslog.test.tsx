import { useState } from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import AccessLogSyslog from '@/pages/xray/basics/AccessLogSyslog';
import BasicsTab from '@/pages/xray/basics/BasicsTab';
import { DEFAULT_ACCESS_LOG_SYSLOG, AccessLogSyslogSchema } from '@/schemas/xray';
import { renderWithProviders } from './test-utils';

function Editor({ logLevelEnabled = true }: { logLevelEnabled?: boolean }) {
  const [value, setValue] = useState(DEFAULT_ACCESS_LOG_SYSLOG);
  return (
    <AccessLogSyslog
      value={value}
      onChange={setValue}
      restartRequired={value.enabled}
      logLevelEnabled={logLevelEnabled}
    />
  );
}

describe('access-log syslog controls', () => {
  it('reveals only receiver settings and preserves them when toggled off and on', () => {
    renderWithProviders(<Editor />);
    expect(screen.queryByRole('textbox', { name: 'Receiver host' })).toBeNull();
    fireEvent.click(screen.getByRole('switch', { name: 'Syslog delivery' }));
    expect(screen.getByText('Saving this switch change will restart Xray.')).toBeTruthy();
    fireEvent.change(screen.getByRole('textbox', { name: 'Receiver host' }), {
      target: { value: 'receiver.example' },
    });
    expect(screen.getByRole('spinbutton', { name: 'Receiver port' })).toHaveProperty(
      'value',
      '514',
    );
    fireEvent.click(screen.getByRole('switch', { name: 'Syslog delivery' }));
    expect(screen.queryByRole('textbox', { name: 'Receiver host' })).toBeNull();
    fireEvent.click(screen.getByRole('switch', { name: 'Syslog delivery' }));
    expect(screen.getByRole('textbox', { name: 'Receiver host' })).toHaveProperty(
      'value',
      'receiver.example',
    );
  });

  it('allows syslog in the log tab when local file logging is disabled', () => {
    renderWithProviders(
      <BasicsTab
        templateSettings={{ log: { access: 'none', loglevel: 'warning' } }}
        setTemplateSettings={vi.fn()}
        outboundTestUrl=""
        onChangeOutboundTestUrl={vi.fn()}
        onResetDefault={vi.fn()}
        accessLogSyslog={{ ...DEFAULT_ACCESS_LOG_SYSLOG, enabled: true, host: 'receiver.example' }}
        onChangeAccessLogSyslog={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole('tab', { name: /\bLog$/ }));
    expect(screen.getByRole('textbox', { name: 'Receiver host' })).toHaveProperty(
      'value',
      'receiver.example',
    );
    expect(
      screen.queryByText('Choose an Xray log level other than none before enabling syslog.'),
    ).toBeNull();
  });

  it('explains only the log-level requirement', () => {
    renderWithProviders(<Editor logLevelEnabled={false} />);
    fireEvent.click(screen.getByRole('switch', { name: 'Syslog delivery' }));
    expect(
      screen.getByText('Choose an Xray log level other than none before enabling syslog.'),
    ).toBeTruthy();
  });

  it('validates the receiver and port', () => {
    expect(AccessLogSyslogSchema.safeParse(DEFAULT_ACCESS_LOG_SYSLOG).success).toBe(true);
    expect(
      AccessLogSyslogSchema.safeParse({
        ...DEFAULT_ACCESS_LOG_SYSLOG,
        port: 0,
        host: 'unfinished/host',
      }).success,
    ).toBe(true);
    expect(
      AccessLogSyslogSchema.safeParse({ ...DEFAULT_ACCESS_LOG_SYSLOG, enabled: true }).success,
    ).toBe(false);
    expect(
      AccessLogSyslogSchema.safeParse({
        ...DEFAULT_ACCESS_LOG_SYSLOG,
        enabled: true,
        host: '2001:db8::1',
      }).success,
    ).toBe(true);
    expect(
      AccessLogSyslogSchema.safeParse({
        ...DEFAULT_ACCESS_LOG_SYSLOG,
        enabled: true,
        host: 'host',
        port: 65536,
      }).success,
    ).toBe(false);
    expect(
      AccessLogSyslogSchema.safeParse({
        ...DEFAULT_ACCESS_LOG_SYSLOG,
        enabled: true,
        host: 'host/path',
      }).success,
    ).toBe(false);
  });
});
