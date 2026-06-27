import {useEffect, useMemo, useState} from 'react'
import {Button, Input, message, Modal, Popconfirm, Space} from 'antd'
import {CheckCircleOutlined, KeyOutlined, PlusOutlined, StopOutlined} from '@ant-design/icons'
import client from '../api/client'
import DataTable from '../components/DataTable'
import {fetchResourceMetadata} from '../api/metadata'
import {getResourceConfig} from '../config/resources'
import type {AuthUser} from '../stores/auth'
import type {CredentialPayload, UserMutationResponse} from '../api/auth'
import type {MetadataResponse} from '../types/records'
import UserCreateModal from './UserCreateModal'
import UserDetailModal from './UserDetailModal'

function credentialMessage(credentials: CredentialPayload) {
  const platformUrl = window.location.origin
  if (credentials.auth_type === 'local') {
    return [
      'Account information',
      `Platform: ${platformUrl}`,
      'Login type: Platform',
      `Username: ${credentials.username}`,
      `Initial password: ${credentials.password || ''}`,
    ].join('\n')
  }
  return [
    'Account information',
    `Platform: ${platformUrl}`,
    'Login type: LDAP',
    `Username: ${credentials.username}`,
    'Use your LDAP password to log in.',
  ].join('\n')
}

export default function UserManagement() {
  const config = useMemo(() => getResourceConfig('users'), [])
  const [metadata, setMetadata] = useState<MetadataResponse | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [selectedUserId, setSelectedUserId] = useState<string | number | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const [credentials, setCredentials] = useState<CredentialPayload | null>(null)

  useEffect(() => {
    fetchResourceMetadata().then(setMetadata).catch(() => setMetadata(null))
  }, [])

  const showCredentials = (nextCredentials: CredentialPayload) => {
    setCredentials(nextCredentials)
  }

  const refresh = () => setRefreshKey((value) => value + 1)
  const messageText = credentials ? credentialMessage(credentials) : ''
  const updateUserStatus = async (record: Record<string, unknown>, isActive: boolean) => {
    try {
      await client.patch(`/auth/users/${record.id}/`, { is_active: isActive })
      message.success(isActive ? 'User enabled' : 'User disabled')
      refresh()
    } catch {
      message.error('Failed to update user status')
    }
  }

  const resetPassword = async (record: Record<string, unknown>) => {
    try {
      const { data } = await client.post<UserMutationResponse>(`/auth/users/${record.id}/reset_password/`)
      showCredentials(data.credentials)
    } catch {
      message.error('Failed to reset password')
    }
  }

  return (
    <div style={{ height: '100%', minHeight: 0 }}>
      <DataTable
        key={refreshKey}
        endpoint={config.endpoint}
        tableKey={config.key}
        rowKey={config.rowKey}
        columns={config.columns}
        filters={config.filters}
        advancedFilters={config.advancedFilters}
        metadata={metadata?.resources?.[config.key]}
        searchPlaceholder={config.searchPlaceholder}
        actions={<Button icon={<PlusOutlined />} onClick={() => setCreateOpen(true)} />}
        actionColumnWidth={128}
        rowActions={(record, defaults) => {
          const user = record as AuthUser & Record<string, unknown>
          const isAdmin = user.role === 'admin'
          return (
            <Space size={4} align="center" className="table-row-actions">
              {!isAdmin ? (
                <Popconfirm
                  title={user.is_active ? 'Disable user?' : 'Enable user?'}
                  onConfirm={(event) => {
                    event?.stopPropagation()
                    return updateUserStatus(user, !user.is_active)
                  }}
                  onCancel={(event) => event?.stopPropagation()}
                >
                  <Button
                    size="small"
                    type="text"
                    icon={user.is_active ? <StopOutlined /> : <CheckCircleOutlined />}
                    onClick={(event) => event.stopPropagation()}
                  />
                </Popconfirm>
              ) : (
                <Button aria-hidden="true" tabIndex={-1} size="small" type="text" icon={<StopOutlined />} disabled style={{ visibility: 'hidden' }} />
              )}
              {!isAdmin && user.auth_type === 'local' ? (
                <Popconfirm
                  title="Reset password?"
                  onConfirm={(event) => {
                    event?.stopPropagation()
                    return resetPassword(user)
                  }}
                  onCancel={(event) => event?.stopPropagation()}
                >
                  <Button size="small" type="text" icon={<KeyOutlined />} onClick={(event) => event.stopPropagation()} />
                </Popconfirm>
              ) : (
                <Button aria-hidden="true" tabIndex={-1} size="small" type="text" icon={<KeyOutlined />} disabled style={{ visibility: 'hidden' }} />
              )}
              {defaults.deleteAction}
            </Space>
          )
        }}
        onRowClick={(record) => setSelectedUserId(record[config.rowKey] as string | number)}
        dense
        fillParent
      />
      <UserCreateModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(response) => {
          setCreateOpen(false)
          refresh()
          message.success('User created')
          showCredentials(response.credentials)
        }}
      />
      <UserDetailModal
        userId={selectedUserId}
        open={selectedUserId !== null}
        onClose={() => setSelectedUserId(null)}
        onSaved={refresh}
      />
      <Modal title="Copy User Login Message" open={credentials !== null} onCancel={() => setCredentials(null)} footer={null} destroyOnClose>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Input.TextArea value={messageText} rows={5} readOnly />
          <Button
            type="primary"
            onClick={() => {
              navigator.clipboard.writeText(messageText)
              message.success('Copied')
            }}
          >
            Copy
          </Button>
        </Space>
      </Modal>
    </div>
  )
}
