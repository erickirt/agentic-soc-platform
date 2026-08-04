import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {
  Button,
  Card,
  Empty,
  Form,
  Input,
  List,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import {DeleteOutlined, EditOutlined, PlusOutlined} from '@ant-design/icons'
import {
  type CaseRelationship,
  type CaseRelationshipInput,
  type CaseRelationshipSuggestion,
  type CaseRelationshipType,
  type RelatedCaseSummary,
  createCaseRelationship,
  deleteCaseRelationship,
  fetchCaseRelationships,
  fetchCaseRelationshipSuggestions,
  searchCases,
  updateCaseRelationship,
} from '../api/caseRelationships'
import {useAuthStore} from '../stores/auth'
import {message} from '../utils/appMessage'
import {formatDateTime, severityTag, statusTag, verdictTag} from '../utils/recordDisplay'

type RelationshipDirection = 'current_to_other' | 'other_to_current'

interface RelationshipFormValues {
  relationship_type: CaseRelationshipType
  direction: RelationshipDirection
  other_case_id: string
  note?: string
}

interface CaseRelationshipsViewProps {
  caseId: string
  onOpenCase?: (caseId: string) => void
  onChanged?: () => void
}

const relationshipTypeOptions = [
  {label: 'Related', value: 'Related'},
  {label: 'Duplicate of', value: 'Duplicate of'},
  {label: 'Parent of', value: 'Parent of'},
]

function apiErrorMessage(error: unknown, fallback: string) {
  const data = (error as {response?: {data?: unknown}}).response?.data
  if (typeof data === 'string') return data
  if (data && typeof data === 'object') {
    const record = data as Record<string, unknown>
    if (typeof record.detail === 'string') return record.detail
    for (const value of Object.values(record)) {
      if (Array.isArray(value) && value.length) return String(value[0])
    }
  }
  return fallback
}

function otherCase(relationship: CaseRelationship, currentCaseId: string) {
  return relationship.source_case.id === currentCaseId
    ? relationship.target_case
    : relationship.source_case
}

function relationLabel(relationship: CaseRelationship, currentCaseId: string) {
  const isSource = relationship.source_case.id === currentCaseId
  if (relationship.relationship_type === 'Related') return 'Related'
  if (relationship.relationship_type === 'Duplicate of') {
    return isSource ? 'Duplicate of' : 'Has duplicate'
  }
  return isSource ? 'Parent of' : 'Child of'
}

function directionFor(relationship: CaseRelationship, currentCaseId: string): RelationshipDirection {
  return relationship.source_case.id === currentCaseId ? 'current_to_other' : 'other_to_current'
}

function relationshipPayload(
  values: RelationshipFormValues,
  currentCaseId: string,
): CaseRelationshipInput {
  const currentIsSource = values.relationship_type === 'Related'
    || values.direction === 'current_to_other'
  return {
    source_case_id: currentIsSource ? currentCaseId : values.other_case_id,
    target_case_id: currentIsSource ? values.other_case_id : currentCaseId,
    relationship_type: values.relationship_type,
    note: values.note?.trim() || '',
  }
}

export default function CaseRelationshipsView({
  caseId,
  onOpenCase,
  onChanged,
}: CaseRelationshipsViewProps) {
  const user = useAuthStore((state) => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'user'
  const [form] = Form.useForm<RelationshipFormValues>()
  const relationshipType = Form.useWatch('relationship_type', form)
  const [relationships, setRelationships] = useState<CaseRelationship[]>([])
  const [relationshipCount, setRelationshipCount] = useState(0)
  const [relationshipPage, setRelationshipPage] = useState(1)
  const [suggestions, setSuggestions] = useState<CaseRelationshipSuggestion[]>([])
  const [caseOptions, setCaseOptions] = useState<RelatedCaseSummary[]>([])
  const [loading, setLoading] = useState(false)
  const [suggestionsLoading, setSuggestionsLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [editing, setEditing] = useState<CaseRelationship | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const searchRequestRef = useRef(0)

  const loadRelationships = useCallback(async () => {
    if (!caseId) return
    setLoading(true)
    try {
      const result = await fetchCaseRelationships(caseId, relationshipPage)
      setRelationships(result.results)
      setRelationshipCount(result.count)
    } catch (error) {
      message.error(apiErrorMessage(error, 'Failed to load Case relationships'))
    } finally {
      setLoading(false)
    }
  }, [caseId, relationshipPage])

  const loadSuggestions = useCallback(async () => {
    if (!caseId) return
    setSuggestionsLoading(true)
    try {
      setSuggestions(await fetchCaseRelationshipSuggestions(caseId))
    } catch (error) {
      message.error(apiErrorMessage(error, 'Failed to load related Case suggestions'))
    } finally {
      setSuggestionsLoading(false)
    }
  }, [caseId])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRelationshipPage(1)
  }, [caseId])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadRelationships()
    void loadSuggestions()
  }, [loadRelationships, loadSuggestions])

  const refresh = useCallback(async () => {
    await Promise.all([loadRelationships(), loadSuggestions()])
    onChanged?.()
  }, [loadRelationships, loadSuggestions, onChanged])

  const loadCaseOptions = useCallback(async (search: string) => {
    const requestId = searchRequestRef.current + 1
    searchRequestRef.current = requestId
    try {
      const cases = await searchCases(search)
      if (requestId === searchRequestRef.current) {
        setCaseOptions(cases.filter((item) => item.id !== caseId))
      }
    } catch (error) {
      if (requestId === searchRequestRef.current) {
        message.error(apiErrorMessage(error, 'Failed to search Cases'))
      }
    }
  }, [caseId])

  const openCreate = () => {
    setEditing(null)
    setCaseOptions([])
    form.resetFields()
    form.setFieldsValue({
      relationship_type: 'Related',
      direction: 'current_to_other',
      note: '',
    })
    setModalOpen(true)
  }

  const openEdit = (relationship: CaseRelationship) => {
    const related = otherCase(relationship, caseId)
    setEditing(relationship)
    setCaseOptions([related])
    form.setFieldsValue({
      relationship_type: relationship.relationship_type,
      direction: directionFor(relationship, caseId),
      other_case_id: related.id,
      note: relationship.note,
    })
    setModalOpen(true)
  }

  const saveRelationship = async () => {
    const values = await form.validateFields()
    setSaving(true)
    try {
      const payload = relationshipPayload(values, caseId)
      if (editing) {
        await updateCaseRelationship(editing.id, payload)
        message.success('Case relationship updated')
      } else {
        await createCaseRelationship(payload)
        message.success('Case relationship created')
      }
      setModalOpen(false)
      await refresh()
    } catch (error) {
      if ((error as {errorFields?: unknown}).errorFields) return
      message.error(apiErrorMessage(error, 'Failed to save Case relationship'))
    } finally {
      setSaving(false)
    }
  }

  const removeRelationship = async (relationship: CaseRelationship) => {
    try {
      await deleteCaseRelationship(relationship.id)
      message.success('Case relationship deleted')
      await refresh()
    } catch (error) {
      message.error(apiErrorMessage(error, 'Failed to delete Case relationship'))
    }
  }

  const acceptSuggestion = async (suggestion: CaseRelationshipSuggestion) => {
    try {
      await createCaseRelationship({
        source_case_id: caseId,
        target_case_id: suggestion.case.id,
        relationship_type: 'Related',
        note: '',
      })
      message.success('Related Case added')
      await refresh()
    } catch (error) {
      message.error(apiErrorMessage(error, 'Failed to add related Case'))
    }
  }

  const caseSelectOptions = useMemo(
    () => caseOptions.map((item) => ({
      value: item.id,
      label: `${item.case_id.toUpperCase()} / ${item.title}`,
    })),
    [caseOptions],
  )

  const columns = [
    {
      title: 'Relationship',
      key: 'relationship',
      width: 140,
      render: (_: unknown, row: CaseRelationship) => <Tag color="blue">{relationLabel(row, caseId)}</Tag>,
    },
    {
      title: 'Case',
      key: 'case',
      render: (_: unknown, row: CaseRelationship) => {
        const related = otherCase(row, caseId)
        return (
          <Space direction="vertical" size={0}>
            <Button type="link" style={{padding: 0}} onClick={() => onOpenCase?.(related.id)}>
              {related.case_id.toUpperCase()}
            </Button>
            <Typography.Text>{related.title}</Typography.Text>
          </Space>
        )
      },
    },
    {
      title: 'Status',
      key: 'status',
      width: 130,
      render: (_: unknown, row: CaseRelationship) => statusTag(otherCase(row, caseId).status),
    },
    {
      title: 'Severity',
      key: 'severity',
      width: 120,
      render: (_: unknown, row: CaseRelationship) => severityTag(otherCase(row, caseId).severity),
    },
    {
      title: 'Verdict',
      key: 'verdict',
      width: 150,
      render: (_: unknown, row: CaseRelationship) => verdictTag(otherCase(row, caseId).verdict),
    },
    {
      title: 'Note',
      dataIndex: 'note',
      key: 'note',
      ellipsis: true,
      render: (value: string) => value || '—',
    },
    {
      title: 'Created',
      key: 'created',
      width: 190,
      render: (_: unknown, row: CaseRelationship) => (
        <Space direction="vertical" size={0}>
          <Typography.Text>{formatDateTime(row.created_at)}</Typography.Text>
          <Typography.Text type="secondary">{row.created_by || 'System'}</Typography.Text>
        </Space>
      ),
    },
    ...(canWrite ? [{
      title: 'Actions',
      key: 'actions',
      width: 100,
      fixed: 'right' as const,
      render: (_: unknown, row: CaseRelationship) => (
        <Space>
          <Tooltip title="Edit relationship">
            <Button type="text" icon={<EditOutlined />} onClick={() => openEdit(row)} />
          </Tooltip>
          <Popconfirm
            title="Delete this relationship?"
            okText="Delete"
            okButtonProps={{danger: true}}
            onConfirm={() => removeRelationship(row)}
          >
            <Tooltip title="Delete relationship">
              <Button type="text" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    }] : []),
  ]

  return (
    <Space direction="vertical" size="middle" style={{width: '100%'}}>
      <Space style={{width: '100%', justifyContent: 'flex-end'}}>
        {canWrite && (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            Add relationship
          </Button>
        )}
      </Space>
      <Table<CaseRelationship>
        rowKey="id"
        loading={loading}
        columns={columns}
        dataSource={relationships}
        pagination={{
          current: relationshipPage,
          pageSize: 20,
          total: relationshipCount,
          showSizeChanger: false,
          onChange: setRelationshipPage,
        }}
        locale={{emptyText: <Empty description="No related Cases" />}}
        scroll={{x: 1100}}
      />
      <Card title="Suggested by shared Artifacts" loading={suggestionsLoading}>
        <List
          dataSource={suggestions}
          locale={{emptyText: 'No suggestions'}}
          renderItem={(suggestion) => (
            <List.Item
              actions={canWrite ? [
                <Popconfirm
                  key="relate"
                  title={`Relate ${suggestion.case.case_id.toUpperCase()} to this Case?`}
                  onConfirm={() => acceptSuggestion(suggestion)}
                >
                  <Button type="link">Add as Related</Button>
                </Popconfirm>,
              ] : undefined}
            >
              <List.Item.Meta
                title={(
                  <Button type="link" style={{padding: 0}} onClick={() => onOpenCase?.(suggestion.case.id)}>
                    {suggestion.case.case_id.toUpperCase()} / {suggestion.case.title}
                  </Button>
                )}
                description={(
                  <Space wrap>
                    <Typography.Text>
                      {suggestion.shared_artifact_count} shared Artifact{suggestion.shared_artifact_count === 1 ? '' : 's'}
                    </Typography.Text>
                    {suggestion.shared_artifacts.map((artifact) => (
                      <Tag key={artifact.id}>{artifact.type}: {artifact.value}</Tag>
                    ))}
                    {suggestion.shared_artifact_count > suggestion.shared_artifacts.length && (
                      <Typography.Text type="secondary">
                        +{suggestion.shared_artifact_count - suggestion.shared_artifacts.length}
                      </Typography.Text>
                    )}
                  </Space>
                )}
              />
            </List.Item>
          )}
        />
      </Card>
      <Modal
        title={editing ? 'Edit Case relationship' : 'Add Case relationship'}
        open={modalOpen}
        confirmLoading={saving}
        okText={editing ? 'Save' : 'Add'}
        onOk={() => void saveRelationship()}
        onCancel={() => setModalOpen(false)}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" preserve={false}>
          <Form.Item
            name="relationship_type"
            label="Relationship"
            rules={[{required: true, message: 'Select a relationship type'}]}
          >
            <Select options={relationshipTypeOptions} />
          </Form.Item>
          {relationshipType !== 'Related' && (
            <Form.Item
              name="direction"
              label="Direction"
              rules={[{required: true, message: 'Select a direction'}]}
            >
              <Select
                options={[
                  {
                    value: 'current_to_other',
                    label: relationshipType === 'Parent of'
                      ? 'This Case is parent of selected Case'
                      : 'This Case is duplicate of selected Case',
                  },
                  {
                    value: 'other_to_current',
                    label: relationshipType === 'Parent of'
                      ? 'Selected Case is parent of this Case'
                      : 'Selected Case is duplicate of this Case',
                  },
                ]}
              />
            </Form.Item>
          )}
          <Form.Item
            name="other_case_id"
            label="Case"
            rules={[{required: true, message: 'Select a Case'}]}
          >
            <Select
              showSearch
              filterOption={false}
              disabled={Boolean(editing)}
              options={caseSelectOptions}
              placeholder="Search by Case ID or title"
              onSearch={(value) => void loadCaseOptions(value)}
              onFocus={() => {
                if (!caseOptions.length) void loadCaseOptions('')
              }}
            />
          </Form.Item>
          <Form.Item
            name="note"
            label="Note"
            rules={[{max: 500, message: 'Note must be 500 characters or fewer'}]}
          >
            <Input.TextArea rows={4} showCount maxLength={500} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
