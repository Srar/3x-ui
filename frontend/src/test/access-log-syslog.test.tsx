import { useState } from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import AccessLogSyslog from '@/pages/xray/basics/AccessLogSyslog';
import { DEFAULT_ACCESS_LOG_SYSLOG, AccessLogSyslogSchema } from '@/schemas/xray';
import { renderWithProviders } from './test-utils';

function Editor({ localLogEnabled = true }: { localLogEnabled?: boolean }) {
  const [value, setValue] = useState(DEFAULT_ACCESS_LOG_SYSLOG);
  return (
    <AccessLogSyslog
      value={value}
      onChange={setValue}
      restartRequired={value.enabled}
      localLogEnabled={localLogEnabled}
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

  it('explains the local-log requirement', () => {
    renderWithProviders(<Editor localLogEnabled={false} />);
    fireEvent.click(screen.getByRole('switch', { name: 'Syslog delivery' }));
    expect(
      screen.getByText(
        'Enable a local access-log file and choose an Xray log level other than none before enabling syslog.',
      ),
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
