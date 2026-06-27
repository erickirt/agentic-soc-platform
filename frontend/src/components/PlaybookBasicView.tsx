import type {ReactNode} from 'react'
import type {DescriptionsProps} from 'antd'
import {Button, Descriptions} from 'antd'
import {DescriptionValue} from './DescriptionValue'
import DetailSectionDivider from './DetailSectionDivider'
import {descriptionStyles} from './descriptionValueStyles'
import {emptyValue} from '../utils/recordDisplay'
import {monoTextStyle} from '../utils/typography'

type RecordRow = Record<string, unknown>

interface PlaybookBasicViewProps {
  record: RecordRow
  onOpenResource?: (resourceKey: string, rowId: string | number) => void
  renderStatus: (value: unknown) => ReactNode
}

const value = (record: RecordRow, key: string) => record[key]
const stringValue = (record: RecordRow, key: string) => emptyValue(value(record, key))
const upperStringValue = (record: RecordRow, key: string) => {
  const displayValue = stringValue(record, key)
  return displayValue === '—' ? displayValue : displayValue.toUpperCase()
}

function Section({ title, items, showTitle = true }: { title?: string; items: DescriptionsProps['items']; showTitle?: boolean }) {
  return (
    <div style={{ marginTop: showTitle ? 16 : 0 }}>
      {showTitle && title && <DetailSectionDivider title={title} />}
      <Descriptions
        size="small"
        layout="vertical"
        colon={false}
        column={4}
        items={items}
        styles={descriptionStyles}
      />
    </div>
  )
}

function item(key: string, label: string, children: ReactNode, span?: number) {
  return {
    key,
    label,
    span,
    children: <DescriptionValue>{children}</DescriptionValue>,
  }
}

function blockItem(key: string, label: string, children: string) {
  return {
    key,
    label,
    span: 4,
    children: <DescriptionValue minHeight={96} height="auto" multiline>{children}</DescriptionValue>,
  }
}

export default function PlaybookBasicView({ record, onOpenResource, renderStatus }: PlaybookBasicViewProps) {
  const caseRowId = value(record, 'case_id') as string | number | null | undefined
  const caseReadableId = upperStringValue(record, 'case_readable_id')
  const caseLabel = caseReadableId === '—'
    ? upperStringValue(record, 'case_id')
    : caseReadableId
  const canOpenCase = Boolean(caseRowId !== null && caseRowId !== undefined && onOpenResource)

  const caseLink = canOpenCase && caseRowId !== null && caseRowId !== undefined ? (
    <Button
      type="link"
      size="small"
      style={{ padding: 0, height: 'auto' }}
      onClick={() => onOpenResource?.('cases', caseRowId)}
    >
      {caseLabel}
    </Button>
  ) : caseLabel

  const summaryItems: DescriptionsProps['items'] = [
    { key: 'playbook-id', label: 'Playbook ID', children: <DescriptionValue mono>{upperStringValue(record, 'playbook_id')}</DescriptionValue> },
    item('status', 'Status', renderStatus(value(record, 'job_status'))),
    item('case', 'Case', caseLink),
    item('user', 'User', stringValue(record, 'user_username')),
    item('name', 'Name', stringValue(record, 'name')),
    { key: 'job-id', label: 'Job ID', children: <DescriptionValue><span style={monoTextStyle}>{stringValue(record, 'job_id')}</span></DescriptionValue> },
  ]

  const inputItems: DescriptionsProps['items'] = [
    blockItem('user-input', 'User Input', stringValue(record, 'user_input')),
    blockItem('remark', 'Remark', stringValue(record, 'remark')),
  ]

  return (
    <div style={{ padding: '20px 20px 16px', overflow: 'auto', height: '100%', boxSizing: 'border-box' }}>
      <Section showTitle={false} items={summaryItems} />
      <Section title="Input & Result" items={inputItems} />
    </div>
  )
}
