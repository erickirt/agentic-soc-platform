import {useCallback, useEffect, useState} from 'react'
import {Alert, Button, Card, Col, Divider, Form, InputNumber, List, message, Row, Select, Space, Tag, Tooltip, Typography} from 'antd'
import {QuestionCircleOutlined} from '@ant-design/icons'
import client from '../api/client'

interface RuntimeConfig {
  prompt_language: 'en' | 'zh'
  stream_maxlen: number
  updated_at?: string
}

interface CustomDefinitionItem {
  name?: string
  source: 'official' | 'custom'
  path: string
  stream_name?: string
  backend?: string
  description?: string
  playbook?: string
  prompt?: string
  language?: string
}

interface CustomDefinitionError {
  path: string
  error: string
}

interface CustomDefinitionSection {
  items: CustomDefinitionItem[]
  errors: CustomDefinitionError[]
}

interface CustomDefinitionRefreshResult {
  success: boolean
  counts: {
    modules: number
    playbooks: number
    siem: number
    prompts: number
    errors: number
  }
  modules: CustomDefinitionSection
  playbooks: CustomDefinitionSection
  siem: CustomDefinitionSection
  prompts: CustomDefinitionSection
}

function initialValues(): RuntimeConfig {
  return {
    prompt_language: 'en',
    stream_maxlen: 10000,
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

function helpLabel(label: string, help: string) {
  return (
    <span>
      {label}
      <Tooltip title={help}>
        <QuestionCircleOutlined style={{ marginLeft: 6, color: 'rgba(255,255,255,0.45)' }} />
      </Tooltip>
    </span>
  )
}

function CustomDefinitionSectionView({ title, section }: { title: string; section: CustomDefinitionSection }) {
  return (
    <div style={{ marginTop: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      <List
        size="small"
        dataSource={section.items}
        locale={{ emptyText: 'No definitions loaded' }}
        renderItem={(item) => (
          <List.Item>
            <Space direction="vertical" size={0}>
              <Space wrap>
                <Typography.Text>{item.name || item.playbook || item.prompt}</Typography.Text>
                <Tag color={item.source === 'custom' ? 'blue' : 'default'}>{item.source}</Tag>
                {item.stream_name ? <Tag>{item.stream_name}</Tag> : null}
                {item.backend ? <Tag>{item.backend}</Tag> : null}
                {item.prompt ? <Tag>{item.prompt}</Tag> : null}
                {item.language ? <Tag>{item.language}</Tag> : null}
              </Space>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{item.path}</Typography.Text>
            </Space>
          </List.Item>
        )}
      />
      {section.errors.map((error) => (
        <Alert
          key={`${title}-${error.path}`}
          type="error"
          showIcon
          style={{ marginTop: 8 }}
          message={error.path}
          description={error.error}
        />
      ))}
    </div>
  )
}

export default function RuntimeSettings() {
  const [form] = Form.useForm<RuntimeConfig>()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [refreshingDefinitions, setRefreshingDefinitions] = useState(false)
  const [definitionResult, setDefinitionResult] = useState<CustomDefinitionRefreshResult | null>(null)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await client.get<RuntimeConfig>('/settings/runtime/')
      form.setFieldsValue({ ...initialValues(), ...data })
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load Runtime configuration'))
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
      const { data } = await client.patch<RuntimeConfig>('/settings/runtime/', values)
      form.setFieldsValue({ ...initialValues(), ...data })
      message.success('Runtime configuration saved')
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save Runtime configuration'))
    } finally {
      setSaving(false)
    }
  }

  const refreshDefinitions = async () => {
    setRefreshingDefinitions(true)
    try {
      const { data } = await client.post<CustomDefinitionRefreshResult>('/settings/runtime/custom-definitions/refresh/')
      setDefinitionResult(data)
      if (data.success) {
        message.success('Custom definitions refreshed')
      } else {
        message.warning(`Custom definitions refreshed with ${data.counts.errors} error(s)`)
      }
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to refresh custom definitions'))
    } finally {
      setRefreshingDefinitions(false)
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0, overflow: 'auto' }}>
      <Card title="Runtime" loading={loading}>
        <Form form={form} layout="vertical" initialValues={initialValues()} style={{ maxWidth: 920 }}>
          <Typography.Text strong>Prompt</Typography.Text>
          <Divider style={{ margin: '8px 0 16px' }} />
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="prompt_language"
                label={helpLabel('Prompt Language', 'Selects the prompt file language used by agentic analysis and extraction prompts.')}
                rules={[{ required: true }]}
              >
                <Select options={[
                  { label: 'English', value: 'en' },
                  { label: '中文', value: 'zh' },
                ]} />
              </Form.Item>
            </Col>
          </Row>

          <Typography.Text strong>Stream Runtime</Typography.Text>
          <Divider style={{ margin: '8px 0 16px' }} />
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="stream_maxlen"
                label={helpLabel('Stream Maxlen', 'Approximate maximum length retained for Redis Streams written by webhook alert ingestion. ELK action processing uses the same webhook write path.')}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={10000000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Space>
            <Button type="primary" onClick={saveConfig} loading={saving}>Save</Button>
          </Space>

          <Typography.Text strong style={{ display: 'block', marginTop: 28 }}>Custom Definitions</Typography.Text>
          <Divider style={{ margin: '8px 0 16px' }} />
          <Typography.Paragraph type="secondary">
            Refresh and validate Module, Playbook, and SIEM YAML definitions after updating files in the custom directory.
            Dependency or helper module changes still require reinstalling custom packages and restarting related containers.
          </Typography.Paragraph>
          <Space>
            <Button onClick={refreshDefinitions} loading={refreshingDefinitions}>Refresh / Validate</Button>
          </Space>
          {definitionResult ? (
            <div style={{ marginTop: 16 }}>
              <Alert
                type={definitionResult.success ? 'success' : 'warning'}
                showIcon
                message={
                  definitionResult.success
                    ? 'Definitions loaded successfully'
                    : `Definitions loaded with ${definitionResult.counts.errors} error(s)`
                }
                description={`Modules: ${definitionResult.counts.modules}, Playbooks: ${definitionResult.counts.playbooks}, SIEM YAML: ${definitionResult.counts.siem}, Prompts: ${definitionResult.counts.prompts}`}
              />
              <Row gutter={16}>
                <Col span={6}>
                  <CustomDefinitionSectionView title="Modules" section={definitionResult.modules} />
                </Col>
                <Col span={6}>
                  <CustomDefinitionSectionView title="Playbooks" section={definitionResult.playbooks} />
                </Col>
                <Col span={6}>
                  <CustomDefinitionSectionView title="SIEM YAML" section={definitionResult.siem} />
                </Col>
                <Col span={6}>
                  <CustomDefinitionSectionView title="Prompts" section={definitionResult.prompts} />
                </Col>
              </Row>
            </div>
          ) : null}
        </Form>
      </Card>
    </div>
  )
}
