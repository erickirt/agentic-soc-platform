import {useMemo, useState} from 'react'
import {App as AntApp, Button, Form, Input, Modal, Popconfirm, Space, Switch, Typography} from 'antd'
import {DeleteOutlined, EditOutlined, EyeOutlined, PlusOutlined} from '@ant-design/icons'
import client from '../api/client'
import DataTable from '../components/DataTable'
import {getResourceConfig} from '../config/resources'
import {message} from '../utils/appMessage'

type CustomVariable = Record<string, unknown> & {
  id: string
  key: string
  value: string
  value_configured: boolean
  is_secret: boolean
  description: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface CustomVariableFormValues {
  key: string
  value?: string
  is_secret: boolean
  description?: string
  enabled: boolean
}

interface RevealedValue {
  key: string
  value: string
}

const MAX_VALUE_BYTES = 65_536

function apiErrorMessage(error: unknown, fallback: string) {
  const data = (error as { response?: { data?: unknown } }).response?.data
  if (typeof data === 'string') return data
  if (data && typeof data === 'object') {
    const detail = (data as { detail?: unknown }).detail
    if (typeof detail === 'string') return detail
    return JSON.stringify(data)
  }
  return fallback
}

function initialValues(): CustomVariableFormValues {
  return {
    key: '',
    value: '',
    is_secret: false,
    description: '',
    enabled: true,
  }
}

export default function CustomVariablesSettings() {
  const {modal} = AntApp.useApp()
  const config = useMemo(() => getResourceConfig('custom-variables'), [])
  const [form] = Form.useForm<CustomVariableFormValues>()
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<CustomVariable | null>(null)
  const [saving, setSaving] = useState(false)
  const [revealingId, setRevealingId] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<RevealedValue | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const isSecret = Form.useWatch('is_secret', form) ?? false

  const refresh = () => setRefreshKey((value) => value + 1)

  const openCreate = () => {
    setEditing(null)
    form.setFieldsValue(initialValues())
    setModalOpen(true)
  }

  const openEdit = async (record: CustomVariable) => {
    try {
      const {data} = await client.get<CustomVariable>(`/custom/variables/${record.id}/`)
      setEditing(data)
      form.setFieldsValue({...initialValues(), ...data})
      setModalOpen(true)
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to load custom variable'))
    }
  }

  const closeEditor = () => {
    setModalOpen(false)
    setEditing(null)
    form.resetFields()
  }

  const persist = async (values: CustomVariableFormValues, confirmSecretExposure: boolean) => {
    const payload: Record<string, unknown> = {
      is_secret: values.is_secret,
      description: values.description || '',
      enabled: values.enabled,
    }
    if (!editing) payload.key = values.key
    if (values.value !== '' && values.value !== undefined) payload.value = values.value
    if (confirmSecretExposure) payload.confirm_secret_exposure = true

    if (editing) {
      await client.patch(`/custom/variables/${editing.id}/`, payload)
      message.success('Custom variable updated')
    } else {
      await client.post('/custom/variables/', payload)
      message.success('Custom variable created')
    }
    closeEditor()
    refresh()
  }

  const saveVariable = async () => {
    setSaving(true)
    try {
      const values = await form.validateFields()
      if (editing?.is_secret && !values.is_secret) {
        modal.confirm({
          title: `Expose ${editing.key} as a non-secret variable?`,
          content: 'This value will become visible in normal Admin API responses and UI.',
          okText: 'Expose value',
          okButtonProps: {danger: true},
          onOk: async () => {
            try {
              await persist(values, true)
            } catch (error: unknown) {
              message.error(apiErrorMessage(error, 'Failed to save custom variable'))
              throw error
            }
          },
        })
      } else {
        await persist(values, false)
      }
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to save custom variable'))
    } finally {
      setSaving(false)
    }
  }

  const revealVariable = async (record: CustomVariable) => {
    setRevealingId(record.id)
    try {
      const {data} = await client.post<{value: string}>(`/custom/variables/${record.id}/reveal/`)
      setRevealed({key: record.key, value: data.value})
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to reveal custom variable'))
    } finally {
      setRevealingId(null)
    }
  }

  const deleteVariable = async (record: CustomVariable) => {
    try {
      await client.delete(`/custom/variables/${record.id}/`)
      message.success('Custom variable deleted')
      refresh()
    } catch (error: unknown) {
      message.error(apiErrorMessage(error, 'Failed to delete custom variable'))
    }
  }

  const validateValue = (_: unknown, value: string | undefined) => {
    if (!value && !editing?.is_secret) {
      return Promise.reject(new Error('Value is required.'))
    }
    if (value !== undefined && new TextEncoder().encode(value).length > MAX_VALUE_BYTES) {
      return Promise.reject(new Error(`Value cannot exceed ${MAX_VALUE_BYTES.toLocaleString()} UTF-8 bytes.`))
    }
    return Promise.resolve()
  }

  return (
    <div style={{height: 'calc(100vh - 188px)', minHeight: 360}}>
      <DataTable
        key={refreshKey}
        endpoint={config.endpoint}
        tableKey={config.key}
        rowKey={config.rowKey}
        columns={config.columns}
        filters={config.filters}
        advancedFilters={config.advancedFilters}
        searchPlaceholder={config.searchPlaceholder}
        actions={<Button icon={<PlusOutlined />} onClick={openCreate} />}
        actionColumnWidth={136}
        rowActions={(record) => {
          const variable = record as CustomVariable
          return (
            <Space size={4} align="center" className="table-row-actions">
              {variable.is_secret ? (
                <Button
                  size="small"
                  type="text"
                  icon={<EyeOutlined />}
                  loading={revealingId === variable.id}
                  onClick={(event) => {
                    event.stopPropagation()
                    revealVariable(variable)
                  }}
                />
              ) : null}
              <Button
                size="small"
                type="text"
                icon={<EditOutlined />}
                onClick={(event) => {
                  event.stopPropagation()
                  openEdit(variable)
                }}
              />
              <Popconfirm
                title={`Delete ${variable.key}?`}
                description="This variable will be permanently deleted."
                okText="Delete"
                okButtonProps={{danger: true}}
                onConfirm={(event) => {
                  event?.stopPropagation()
                  return deleteVariable(variable)
                }}
                onCancel={(event) => event?.stopPropagation()}
              >
                <Button
                  size="small"
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                  onClick={(event) => event.stopPropagation()}
                />
              </Popconfirm>
            </Space>
          )
        }}
        onRowClick={(record) => openEdit(record as CustomVariable)}
        dense
        fillParent
      />

      <Modal
        title={editing ? `Custom Variable: ${editing.key}` : 'Add Custom Variable'}
        open={modalOpen}
        onCancel={closeEditor}
        destroyOnHidden
        footer={(
          <Space>
            <Button onClick={closeEditor}>Cancel</Button>
            <Button type="primary" loading={saving} onClick={saveVariable}>Save</Button>
          </Space>
        )}
      >
        <Form form={form} layout="vertical" initialValues={initialValues()} style={{paddingTop: 8}}>
          <Form.Item
            name="key"
            label="Key"
            rules={[
              {required: true},
              {pattern: /^[A-Z][A-Z0-9_]{0,127}$/, message: 'Use uppercase letters, numbers, and underscores.'},
            ]}
          >
            <Input disabled={editing !== null} placeholder="EDR_API_TOKEN" maxLength={128} />
          </Form.Item>
          <Form.Item
            name="value"
            label="Value"
            rules={[{validator: validateValue}]}
            extra={editing?.is_secret
              ? 'Leave blank to keep the current value. Maximum 65,536 UTF-8 bytes.'
              : 'Maximum 65,536 UTF-8 bytes.'}
          >
            {isSecret
              ? <Input.Password autoComplete="new-password" />
              : <Input.TextArea autoSize={{minRows: 3, maxRows: 10}} />}
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea autoSize={{minRows: 2, maxRows: 5}} />
          </Form.Item>
          <Form.Item name="is_secret" label="Secret" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={revealed ? `Secret: ${revealed.key}` : 'Secret'}
        open={revealed !== null}
        onCancel={() => setRevealed(null)}
        destroyOnHidden
        footer={<Button onClick={() => setRevealed(null)}>Close</Button>}
      >
        <Typography.Paragraph type="secondary">
          This value is shown only in this dialog.
        </Typography.Paragraph>
        <Input.TextArea value={revealed?.value || ''} readOnly autoSize={{minRows: 2, maxRows: 10}} />
      </Modal>
    </div>
  )
}
