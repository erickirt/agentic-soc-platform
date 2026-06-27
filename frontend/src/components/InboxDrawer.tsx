import {useCallback, useEffect, useState} from 'react'
import {Alert, Badge, Button, Drawer, Empty, List, message, Popconfirm, Segmented, Space, Spin, Tag, Tooltip, Typography} from 'antd'
import {CheckCircleOutlined, CloseOutlined, InboxOutlined, MailOutlined, MessageOutlined, ReloadOutlined} from '@ant-design/icons'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import {comfortableTagProps} from '../utils/tagStyles'
import {
    createInboxMessage,
    deleteInboxMessage,
    fetchInboxMessage,
    fetchInboxMessages,
    fetchInboxUnreadCount,
    type InboxMessage,
    markAllInboxMessagesRead,
    replyInboxMessage,
} from '../api/inbox'
import {useAuthStore} from '../stores/auth'
import useCursorFeed from '../hooks/useCursorFeed'
import FeedLoadMore from './FeedLoadMore'
import MessageAttachments from './MessageAttachments'
import MessageComposer from './MessageComposer'
import UserAvatar from './UserAvatar'
import {tabularNumbersStyle, typography} from '../utils/typography'

dayjs.extend(relativeTime)

interface InboxDrawerProps {
  onOpenResource?: (resourceKey: string, rowId: string | number) => void
}

const INBOX_UNREAD_POLL_INTERVAL_MS = 60000

function senderLabel(row: InboxMessage) {
  if (row.kind === 'system') return 'System'
  return row.sender_name || row.sender_username || 'Unknown user'
}

function messagePreview(row: InboxMessage) {
  if (row.body.trim()) return row.body
  if (row.attachments.length) return `${row.attachments.length} attachment${row.attachments.length > 1 ? 's' : ''}`
  return 'No content'
}

function timeLabel(value: string) {
  const timestamp = dayjs(value)
  if (!timestamp.isValid()) return value
  return timestamp.fromNow()
}

function parentLabel(row: InboxMessage) {
  return row.parent_author_name || row.parent_author_username || 'Unknown user'
}

function ReplyContext({ row }: { row: InboxMessage }) {
  if (!row.parent) return null
  return (
    <>
      <span style={{ color: 'rgba(255,255,255,0.45)' }}> replied to </span>
      <span>{parentLabel(row)}</span>
      <Tooltip title={row.parent_body || 'No text content'}>
        <MessageOutlined style={{ color: 'rgba(255,255,255,0.45)', fontSize: typography.compact.fontSize, marginInlineStart: 4 }} />
      </Tooltip>
    </>
  )
}

function resourceName(resourceKey: string) {
  const names: Record<string, string> = {
    cases: 'case',
    alerts: 'alert',
    artifacts: 'artifact',
    enrichments: 'enrichment',
    playbooks: 'playbook',
    knowledge: 'knowledge',
    users: 'user',
  }
  return names[resourceKey] || resourceKey
}

function RecordLink({ message: row, onOpenResource }: { message: InboxMessage; onOpenResource?: (resourceKey: string, rowId: string | number) => void }) {
  if (!row.resource_key || !row.object_id) return null
  const canOpen = Boolean(onOpenResource)
  const label = row.resource_label || row.object_id || 'related record'
  return (
    <div style={{ ...typography.compact, marginTop: 6, color: 'rgba(255,255,255,0.68)', minWidth: 0 }}>
      <span>{resourceName(row.resource_key)}: </span>
      {canOpen ? (
        <Button
          type="link"
          size="small"
          style={{ ...typography.compact, padding: 0, height: 'auto' }}
          onClick={(event) => {
            event.stopPropagation()
            onOpenResource?.(row.resource_key, row.object_id)
          }}
        >
          {label}
        </Button>
      ) : (
        <span style={{ color: 'rgba(255,255,255,0.88)' }}>{label}</span>
      )}
    </div>
  )
}

function MessageBody({ row, onOpenResource }: { row: InboxMessage; onOpenResource?: (resourceKey: string, rowId: string | number) => void }) {
  return (
    <div style={{ display: 'grid', gap: 8, minWidth: 0 }}>
      {row.body && <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{row.body}</Typography.Paragraph>}
      <MessageAttachments attachments={row.attachments || []} />
      <RecordLink message={row} onOpenResource={onOpenResource} />
    </div>
  )
}

function DeleteMessageAction({ onDelete }: { onDelete: () => Promise<void> }) {
  return (
    <span onClick={(event) => event.stopPropagation()}>
      <Popconfirm
        title="Delete message?"
        description="Recipients will no longer see this message."
        okText="Delete"
        cancelText="Cancel"
        okButtonProps={{ danger: true }}
        onConfirm={onDelete}
      >
        <Button type="link" danger size="small" style={{ padding: 0 }}>Delete</Button>
      </Popconfirm>
    </span>
  )
}

export default function InboxDrawer({ onOpenResource }: InboxDrawerProps) {
  const currentUser = useAuthStore((state) => state.user)
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState<'all' | 'unread'>('all')
  const [selected, setSelected] = useState<InboxMessage | null>(null)
  const [replyTo, setReplyTo] = useState<InboxMessage | null>(null)
  const [unreadCount, setUnreadCount] = useState(0)
  const [refreshingCount, setRefreshingCount] = useState(false)

  const fetchInboxPage = useCallback((cursor?: string | null) => (
    fetchInboxMessages({ unread: filter === 'unread', cursor, pageSize: 20 })
  ), [filter])

  const {
    items: rows,
    setItems: setRows,
    loadingInitial,
    loadingMore,
    hasMore,
    error: loadError,
    refresh: refreshMessages,
    loadMore,
  } = useCursorFeed({
    enabled: open,
    fetchPage: fetchInboxPage,
    getItemKey: (row) => row.id,
    errorMessage: 'Failed to load messages',
  })

  const loadUnreadCount = useCallback(async () => {
    setRefreshingCount(true)
    try {
      setUnreadCount(await fetchInboxUnreadCount())
    } catch {
      setUnreadCount(0)
    } finally {
      setRefreshingCount(false)
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadUnreadCount()
    const timer = window.setInterval(loadUnreadCount, INBOX_UNREAD_POLL_INTERVAL_MS)
    return () => window.clearInterval(timer)
  }, [loadUnreadCount])

  const canReply = (row: InboxMessage) => {
    return Boolean(row.kind === 'user' && row.sender && row.sender !== currentUser?.id)
  }

  const openMessage = async (row: InboxMessage) => {
    try {
      const detail = await fetchInboxMessage(row.id)
      setSelected(detail)
      setRows((current) => current.map((item) => item.id === detail.id ? detail : item))
      await loadUnreadCount()
    } catch {
      message.error('Failed to open message')
    }
  }

  const deleteMessage = async (row: InboxMessage) => {
    try {
      await deleteInboxMessage(row.id)
      message.success('Message deleted')
      if (selected?.id === row.id) {
        setSelected(null)
      }
      if (replyTo?.id === row.id) setReplyTo(null)
      await Promise.all([refreshMessages(), loadUnreadCount()])
    } catch {
      message.error('Failed to delete message')
    }
  }

  const submitMessage = async (input: { body: string; mentionedIds: number[]; attachments: { id: number }[] }) => {
    if (replyTo) {
      await replyInboxMessage(replyTo.id, {
        body: input.body,
        attachments: input.attachments.map((attachment) => attachment.id),
      })
      setReplyTo(null)
      message.success('Reply sent')
      await Promise.all([refreshMessages(), loadUnreadCount()])
      return
    }

    if (!input.mentionedIds.length) {
      message.warning('Mention at least one user to send a message')
      return
    }
    await createInboxMessage({
      body: input.body,
      recipients: input.mentionedIds,
      attachments: input.attachments.map((attachment) => attachment.id),
    })
    message.success('Message sent')
    await Promise.all([refreshMessages(), loadUnreadCount()])
  }

  return (
    <>
      <Badge count={unreadCount} size="small" offset={[-2, 5]}>
        <Button
          type="text"
          size="large"
          icon={<MessageOutlined style={{ fontSize: 16 }} />}
          loading={refreshingCount}
          style={{ color: 'rgba(255,255,255,0.85)' }}
          onClick={() => setOpen(true)}
        />
      </Badge>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        closable={false}
        size={560}
        styles={{ body: { padding: 0, display: 'flex', flexDirection: 'column', minHeight: 0, overflowX: 'hidden' } }}
      >
        <div style={{ padding: 12, borderBottom: '1px solid #303030' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
            <Space>
              <Segmented
                value={filter}
                options={[
                  { label: <Tooltip title="All messages"><InboxOutlined /></Tooltip>, value: 'all' },
                  { label: <Tooltip title="Unread messages"><MailOutlined /></Tooltip>, value: 'unread' },
                ]}
                onChange={(value) => {
                  setSelected(null)
                  setReplyTo(null)
                  setFilter(value as 'all' | 'unread')
                }}
              />
              <Space>
                <Tooltip title="Mark all read">
                  <Button
                    icon={<CheckCircleOutlined />}
                    onClick={async () => {
                      await markAllInboxMessagesRead()
                      await Promise.all([refreshMessages(), loadUnreadCount()])
                    }}
                  />
                </Tooltip>
                <Tooltip title="Refresh messages">
                  <Button icon={<ReloadOutlined />} onClick={() => Promise.all([refreshMessages(), loadUnreadCount()])} />
                </Tooltip>
              </Space>
            </Space>
            <Tooltip title="Close">
              <Button icon={<CloseOutlined />} onClick={() => setOpen(false)} />
            </Tooltip>
          </div>
        </div>
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', overflowX: 'hidden' }}>
          {loadingInitial ? (
            <Spin style={{ margin: 24 }} />
          ) : rows.length ? (
            <>
              {loadError && <Alert type="error" title={loadError} showIcon style={{ margin: 12 }} />}
              <List
                dataSource={rows}
                loadMore={hasMore ? (
                  <div style={{paddingInline: 16}}>
                    <FeedLoadMore loading={loadingMore} onClick={loadMore} />
                  </div>
                ) : null}
                renderItem={(row) => (
                  <List.Item
                    onClick={() => openMessage(row)}
                    style={{
                      cursor: 'pointer',
                      display: 'block',
                      padding: 16,
                      boxSizing: 'border-box',
                      minWidth: 0,
                      overflow: 'hidden',
                      borderInlineStart: selected?.id === row.id ? '3px solid #1677ff' : '3px solid transparent',
                      background: row.is_read ? 'transparent' : 'rgba(22, 119, 255, 0.08)',
                    }}
                  >
                    <List.Item.Meta
                      avatar={(
                        <Badge dot={!row.is_read}>
                          <UserAvatar username={senderLabel(row)} avatarUrl={row.sender_avatar_url} />
                        </Badge>
                      )}
                      title={(
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                          <Space size={8} wrap>
                            <Tag {...comfortableTagProps} color={row.kind === 'system' ? 'purple' : 'blue'} style={{ marginInlineEnd: 0 }}>
                              {row.kind}
                            </Tag>
                            <Typography.Text strong={!row.is_read}>{senderLabel(row)}</Typography.Text>
                            <ReplyContext row={row} />
                          </Space>
                          <Tooltip title={new Date(row.created_at).toLocaleString()}>
                            <Typography.Text type="secondary" style={{ ...typography.compact, ...tabularNumbersStyle, whiteSpace: 'nowrap' }}>
                              {timeLabel(row.created_at)}
                            </Typography.Text>
                          </Tooltip>
                        </div>
                      )}
                      description={(
                        <div style={{ display: 'grid', gap: 8 }}>
                          {selected?.id === row.id && selected ? (
                            <MessageBody row={selected} onOpenResource={onOpenResource} />
                          ) : (
                            <>
                              <Typography.Text ellipsis style={{ color: 'rgba(255,255,255,0.65)' }}>
                                {messagePreview(row)}
                              </Typography.Text>
                              <RecordLink message={row} onOpenResource={onOpenResource} />
                            </>
                          )}
                        </div>
                      )}
                    />
                    {selected?.id === row.id && selected && (
                      <div
                        style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingLeft: 40 }}
                        onClick={(event) => event.stopPropagation()}
                      >
                        {canReply(selected) && (
                          <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setReplyTo(selected)}>
                            Reply
                          </Button>
                        )}
                        {selected.can_delete && <DeleteMessageAction onDelete={() => deleteMessage(selected)} />}
                      </div>
                    )}
                  </List.Item>
                  )}
              />
            </>
          ) : loadError ? (
            <Alert type="error" title={loadError} showIcon style={{ margin: 24 }} />
          ) : (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No messages" style={{ marginTop: 48 }} />
          )}
        </div>
        {replyTo && (
          <div style={{ color: 'rgba(255,255,255,0.45)', padding: '8px 12px 0' }}>
            Replying to {senderLabel(replyTo)}
            <Button type="link" size="small" onClick={() => setReplyTo(null)}>Cancel</Button>
          </div>
        )}
        <div style={{ padding: 12, borderTop: '1px solid #303030' }}>
          <MessageComposer
            compact
            submitLabel={replyTo ? 'Reply' : 'Send'}
            onSubmit={submitMessage}
          />
        </div>
      </Drawer>
    </>
  )
}
