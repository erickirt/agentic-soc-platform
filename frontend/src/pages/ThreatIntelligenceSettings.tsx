import {useCallback, useEffect, useState} from 'react'
import {Button, Card, Form, Input, InputNumber, message, Space, Switch} from 'antd'
import client from '../api/client'

interface AlienVaultOTXConfig {
  enabled: boolean
  api_key: string
  api_key_configured: boolean
  base_url: string
  proxy: string
  timeout_seconds: number
  updated_at?: string
}

interface OTXTestResult {
  success: boolean
  detail: string
  response_preview?: string
}

function initialValues(): AlienVaultOTXConfig {
  return {
    enabled: false,
    api_key: '',
    api_key_configured: false,
    base_url: 'https://otx.alienvault.com/api/v1',
    proxy: '',
    timeout_seconds: 10,
  }
}

function apiErrorMessage(error: unknown, fallback: string) {
  const response = error as { response?: { data?: unknown } }
  const data = response.response?.data
  if (!data) return fallback
  if (typeof data === 'string') return data
  if (typeof data === 'object') {
    const detail = (data as { detail?: unknown }).detail
    if (typeof detail === 'string') return detail
    return JSON.stringify(data)
  }
  return fallback
}

export default function ThreatIntelligenceSettings() {
  const [form] = Form.useForm<AlienVaultOTXConfig>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await client.get<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
        params: { reveal_secrets: true },
      })
      form.setFieldsValue({ ...initialValues(), ...data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load AlienVault OTX configuration'))
    } finally {
      setLoading(false)
    }
  }, [form])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConfig()
  }, [loadConfig])

  const saveConfig = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      const { data } = await client.patch<AlienVaultOTXConfig>('/settings/threat-intel/otx/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      form.setFieldsValue({ ...initialValues(), ...data, api_key: values.api_key || '' })
      message.success('AlienVault OTX configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save AlienVault OTX configuration'))
    } finally {
      setSaving(false)
    }
  }

  const testConfig = async () => {
    setTesting(true)
    try {
      const values = await form.validateFields()
      const { data } = await client.post<OTXTestResult>('/settings/threat-intel/otx/test/', {
        ...values,
        api_key: values.api_key || '',
        proxy: values.proxy || '',
      })
      if (data.success) message.success(data.detail)
      else message.error(data.detail)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to test AlienVault OTX configuration'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Card title="AlienVault OTX" loading={loading}>
        <Form form={form} layout="vertical" initialValues={initialValues()} style={{ maxWidth: 760 }}>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="base_url" label="Base URL" rules={[{ required: true }, { type: 'url' }]}>
            <Input placeholder="https://otx.alienvault.com/api/v1" />
          </Form.Item>
          <Form.Item name="api_key" label="API Key" rules={[{ required: true, message: 'API key is required' }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="proxy" label="Proxy">
            <Input placeholder="http://127.0.0.1:7890" />
          </Form.Item>
          <Form.Item name="timeout_seconds" label="Timeout Seconds" rules={[{ required: true }]}>
            <InputNumber min={1} max={300} style={{ width: 180 }} />
          </Form.Item>
          <Space>
            <Button onClick={testConfig} loading={testing}>Test</Button>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>
        </Form>
      </Card>
    </div>
  )
}
