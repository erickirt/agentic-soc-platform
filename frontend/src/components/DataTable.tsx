import type {Key} from 'react'
import {useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState} from 'react'
import {Button, Checkbox, Divider, Input, message, Pagination, Popconfirm, Popover, Select, Space, Table, Tooltip} from 'antd'
import {ClearOutlined, CloseOutlined, DeleteOutlined, FilterOutlined, HolderOutlined, ReloadOutlined, SettingOutlined} from '@ant-design/icons'
import {closestCenter, DndContext, type DragEndEvent, PointerSensor, useSensor, useSensors} from '@dnd-kit/core'
import {arrayMove, SortableContext, useSortable, verticalListSortingStrategy} from '@dnd-kit/sortable'
import {CSS} from '@dnd-kit/utilities'
import type {ColumnsType, TableProps} from 'antd/es/table'
import client from '../api/client'
import type {AdvancedFilterCondition, AdvancedFilterFieldConfig, OpenResourceOptions, ResourceColumn, ResourceFilterConfig, ResourceMetadata, TableFilterState} from '../types/records'
import TableFilterModal, {TABLE_FILTER_MODAL_WIDTH} from './TableFilterModal'

interface DataTableProps<RecordType extends Record<string, unknown> = Record<string, unknown>> {
  endpoint: string
  tableKey?: string
  savedFiltersKey?: string
  rowKey?: string
  columns: ColumnsType<RecordType> | ResourceColumn<RecordType>[]
  filters?: ResourceFilterConfig[]
  advancedFilters?: AdvancedFilterFieldConfig[]
  metadata?: ResourceMetadata
  onRowClick?: (record: RecordType, options?: { tabKey?: string }) => void
  onOpenResource?: (resourceKey: string, rowId: string | number, options?: OpenResourceOptions) => void
  searchPlaceholder?: string
  actions?: React.ReactNode
  rowActions?: (record: RecordType, defaults: { deleteAction: React.ReactNode }) => React.ReactNode
  rowSelectionDisabled?: (record: RecordType) => boolean
  actionColumnWidth?: number
  dense?: boolean
  fillParent?: boolean
  baseParams?: Record<string, string | number | boolean | undefined>
  refreshToken?: unknown
}

const PAGE_SIZE_OPTIONS = [20, 50, 100]
const TABLE_BOTTOM_GAP = 0
const MIN_TABLE_BODY_HEIGHT = 160
const DEFAULT_COLUMN_WIDTH = 160
const ROW_SELECTION_COLUMN_WIDTH = 48
const tableDataRequests = new Map<string, Promise<unknown>>()

function storageKey(tableKey: string, suffix: string) {
  return `asp:${tableKey}:${suffix}`
}

function tableRequestKey(endpoint: string, params: Record<string, string | number | boolean | undefined>) {
  const query = Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== '')
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${String(value)}`)
    .join('&')
  return `${endpoint}?${query}`
}

function stableParamsKey(params: Record<string, string | number | boolean | undefined> = {}) {
  return JSON.stringify(
    Object.entries(params)
      .filter(([, value]) => value !== undefined)
      .sort(([left], [right]) => left.localeCompare(right)),
  )
}

function paramsFromKey(key: string): Record<string, string | number | boolean | undefined> {
  return Object.fromEntries(JSON.parse(key) as [string, string | number | boolean][])
}

function fetchTableData(endpoint: string, params: Record<string, string | number | boolean | undefined>) {
  const key = tableRequestKey(endpoint, params)
  const existingRequest = tableDataRequests.get(key)
  if (existingRequest) return existingRequest

  const request = client.get(endpoint, { params })
    .then((response) => response.data)
    .finally(() => {
      if (tableDataRequests.get(key) === request) {
        tableDataRequests.delete(key)
      }
    })

  tableDataRequests.set(key, request)
  return request
}

function readNumber(key: string, fallback: number) {
  const value = Number(localStorage.getItem(key))
  return PAGE_SIZE_OPTIONS.includes(value) ? value : fallback
}

function emptyFilterState(): TableFilterState {
  return { quick: {}, advanced: [] }
}

function hasFilterValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value.length > 0 : Boolean(value)
}

function isActiveAdvancedFilter(condition: AdvancedFilterCondition) {
  if (!condition.field || !condition.operator) return false
  if (condition.operator === 'is_empty' || condition.operator === 'is_not_empty') return true
  return hasFilterValue(condition.value)
}

function columnKey(column: Record<string, unknown>, index: number) {
  const key = column.key || column.dataIndex || column.title || index
  return String(key)
}

function isLockedColumn(column: Record<string, unknown>) {
  return Boolean(column.required || column.fixed)
}

function columnScrollWidth(column: Record<string, unknown>) {
  return typeof column.width === 'number' && Number.isFinite(column.width)
    ? column.width
    : DEFAULT_COLUMN_WIDTH
}

interface ColumnSettings {
  visible: Set<string>
  order: string[]
}

function normalizeColumnOrder(order: string[] | undefined, columns: Record<string, unknown>[]) {
  const keys = columns.map((column) => String(column.key))
  const validOrder = (order || []).filter((key) => keys.includes(key))
  return [...validOrder, ...keys.filter((key) => !validOrder.includes(key))]
}

function saveColumnSettings(tableKey: string, visible: Set<string>, order: string[]) {
  localStorage.setItem(storageKey(tableKey, 'columnSettings'), JSON.stringify({
    visible: [...visible],
    order,
  }))
}

function readColumnSettings(tableKey: string, columns: Record<string, unknown>[]): ColumnSettings {
  const lockedKeys = columns
    .filter(isLockedColumn)
    .map((column) => String(column.key))
  const savedSettings = localStorage.getItem(storageKey(tableKey, 'columnSettings'))
  if (savedSettings) {
    try {
      const parsed = JSON.parse(savedSettings) as { visible?: string[]; order?: string[] }
      const keys = columns.map((column) => String(column.key))
      return {
        visible: new Set([...(parsed.visible || []).filter((key) => keys.includes(key)), ...lockedKeys]),
        order: normalizeColumnOrder(parsed.order, columns),
      }
    } catch {
      localStorage.removeItem(storageKey(tableKey, 'columnSettings'))
    }
  }

  const saved = localStorage.getItem(storageKey(tableKey, 'columns'))
  if (saved) {
    try {
      const keys = columns.map((column) => String(column.key))
      return {
        visible: new Set([...(JSON.parse(saved) as string[]).filter((key) => keys.includes(key)), ...lockedKeys]),
        order: normalizeColumnOrder(undefined, columns),
      }
    } catch {
      localStorage.removeItem(storageKey(tableKey, 'columns'))
    }
  }
  return {
    visible: new Set(
      columns
        .filter((column) => isLockedColumn(column) || column.defaultVisible !== false)
        .map((column) => String(column.key)),
    ),
    order: normalizeColumnOrder(undefined, columns),
  }
}

function SortableColumnSetting({
  columnKey,
  title,
  checked,
  locked,
  onToggle,
}: {
  columnKey: string
  title: string
  checked: boolean
  locked: boolean
  onToggle: (key: string) => void
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: columnKey,
    disabled: locked,
  })

  return (
    <div
      ref={setNodeRef}
      style={{
        transform: CSS.Transform.toString(transform),
        transition,
        opacity: isDragging ? 0.65 : 1,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '6px 8px',
        borderRadius: 6,
        cursor: locked ? 'default' : 'pointer',
      }}
      onClick={() => onToggle(columnKey)}
    >
      <Button
        type="text"
        size="small"
        icon={<HolderOutlined />}
        disabled={locked}
        style={{ cursor: locked ? 'not-allowed' : 'grab' }}
        {...attributes}
        {...listeners}
        onClick={(event) => event.stopPropagation()}
      />
      <Checkbox
        checked={checked}
        disabled={locked}
        onClick={(event) => event.stopPropagation()}
        onChange={() => onToggle(columnKey)}
      >
        {title}
      </Checkbox>
    </div>
  )
}

export default function DataTable<RecordType extends Record<string, unknown> = Record<string, unknown>>({
  endpoint,
  tableKey,
  savedFiltersKey,
  rowKey = 'id',
  columns,
  filters,
  advancedFilters,
  metadata,
  onRowClick,
  onOpenResource,
  searchPlaceholder = 'Search...',
  actions,
  rowActions,
  rowSelectionDisabled,
  actionColumnWidth = 96,
  dense = true,
  fillParent = false,
  baseParams,
  refreshToken,
}: DataTableProps<RecordType>) {
  const resolvedTableKey = tableKey || endpoint
  const resolvedSavedFiltersKey = savedFiltersKey || resolvedTableKey
  const normalizedColumns = useMemo<Record<string, unknown>[]>(
    () => (columns as Record<string, unknown>[]).map((column, index) => ({
      ...column,
      key: columnKey(column, index),
    })),
    [columns],
  )
  const initialColumnSettings = useMemo(
    () => readColumnSettings(resolvedTableKey, normalizedColumns),
    [resolvedTableKey, normalizedColumns],
  )
  const [data, setData] = useState<RecordType[]>([])
  const [loading, setLoading] = useState(false)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(() => readNumber(storageKey(resolvedTableKey, 'pageSize'), 20))
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [ordering, setOrdering] = useState('')
  const [filterState, setFilterState] = useState<TableFilterState>(() => emptyFilterState())
  const [filterModalOpen, setFilterModalOpen] = useState(false)
  const [filterModalPosition, setFilterModalPosition] = useState<{ top: number; left: number }>()
  const [savedFilterName, setSavedFilterName] = useState('')
  const [userOptions, setUserOptions] = useState<{ label: string; value: string }[]>([])
  const [tableResetKey, setTableResetKey] = useState(0)
  const [visibleColumns, setVisibleColumns] = useState(initialColumnSettings.visible)
  const [columnOrder, setColumnOrder] = useState(initialColumnSettings.order)
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([])
  const [selectedRows, setSelectedRows] = useState<RecordType[]>([])
  const containerRef = useRef<HTMLDivElement>(null)
  const toolbarRef = useRef<HTMLDivElement>(null)
  const filterButtonRef = useRef<HTMLButtonElement>(null)
  const requestIdRef = useRef(0)
  const mountedRef = useRef(true)
  const [tableBodyHeight, setTableBodyHeight] = useState(520)
  const baseParamsKey = useMemo(() => stableParamsKey(baseParams), [baseParams])
  const stableBaseParams = useMemo(() => paramsFromKey(baseParamsKey), [baseParamsKey])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      requestIdRef.current += 1
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setVisibleColumns(initialColumnSettings.visible)
    setColumnOrder(initialColumnSettings.order)
  }, [initialColumnSettings])

  const fetchData = useCallback(async () => {
    const requestId = requestIdRef.current + 1
    requestIdRef.current = requestId
    setLoading(true)
    try {
      const params: Record<string, string | number | boolean | undefined> = { ...stableBaseParams, page, page_size: pageSize }
      if (search) params.search = search
      if (ordering) params.ordering = ordering
      for (const [key, value] of Object.entries(filterState.quick)) {
        if (hasFilterValue(value)) params[key] = Array.isArray(value) ? value.join(',') : value
      }
      const activeAdvancedFilters = filterState.advanced
        .filter(isActiveAdvancedFilter)
        .map(({ connector, field, operator, value }) => ({ connector, field, operator, value }))
      if (activeAdvancedFilters.length > 0) {
        params.advanced_filters = JSON.stringify(activeAdvancedFilters)
      }
      const responseData = await fetchTableData(endpoint, params)
      if (!mountedRef.current || requestId !== requestIdRef.current) return
      const rows = responseData as { results?: RecordType[]; count?: number } | RecordType[]
      setData(Array.isArray(rows) ? rows : rows.results || [])
      setTotal(Array.isArray(rows) ? rows.length : rows.count || 0)
      setSelectedRowKeys([])
      setSelectedRows([])
    } catch {
      if (!mountedRef.current || requestId !== requestIdRef.current) return
      message.error('Failed to load table data')
    } finally {
      if (mountedRef.current && requestId === requestIdRef.current) {
        setLoading(false)
      }
    }
  }, [endpoint, filterState, ordering, page, pageSize, search, stableBaseParams])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchData()
  }, [fetchData, refreshToken])

  useEffect(() => {
    if (!filters?.some((filter) => filter.valueType === 'user')) return
    client.get('/auth/user-options/')
      .then(({ data }) => setUserOptions(data))
      .catch(() => setUserOptions([]))
  }, [filters])

  const filterOptions = (filter: ResourceFilterConfig) => {
    const options = filter.valueType === 'user'
      ? userOptions
      : filter.options || metadata?.choices?.[filter.key] || []
    const column = normalizedColumns.find((item) => String(item.key) === filter.key || String(item.dataIndex) === filter.key)
    const render = column?.render as ((value: unknown, record: RecordType, index: number) => React.ReactNode) | undefined

    return options.map((option) => ({
      ...option,
      label: render ? render(option.value, { [filter.key]: option.value } as RecordType, 0) : option.label,
    }))
  }

  const updateQuickFilter = (key: string, value: string | string[] | undefined) => {
    setSavedFilterName('')
    setFilterState((previous) => ({
      ...previous,
      quick: {
        ...previous.quick,
        [key]: value || '',
      },
    }))
    setPage(1)
  }

  const handleDelete = useCallback(async (record: RecordType) => {
    const recordId = record[rowKey]
    if (recordId === undefined || recordId === null) {
      message.error('Cannot delete row without an ID')
      return
    }
    try {
      await client.delete(`${endpoint}${recordId}/`)
      message.success('Record deleted')
      fetchData()
    } catch {
      message.error('Failed to delete record')
    }
  }, [endpoint, fetchData, rowKey])

  const handleBulkDelete = useCallback(async () => {
    const recordIds = selectedRows
      .map((record) => record[rowKey])
      .filter((recordId) => recordId !== undefined && recordId !== null)

    if (recordIds.length !== selectedRows.length) {
      message.error('Cannot delete selected rows without IDs')
      return
    }

    try {
      await Promise.all(recordIds.map((recordId) => client.delete(`${endpoint}${recordId}/`)))
      message.success(`${recordIds.length} record(s) deleted`)
      setSelectedRowKeys([])
      setSelectedRows([])
      fetchData()
    } catch {
      message.error('Failed to delete selected records')
    }
  }, [endpoint, fetchData, rowKey, selectedRows])

  const antColumns = useMemo(() => {
    const normalizedColumnMap = new Map(normalizedColumns.map((column) => [String(column.key), column]))
    const orderedColumns = columnOrder
      .map((key) => normalizedColumnMap.get(key))
      .filter((column): column is Record<string, unknown> => Boolean(column))
    const visibleDataColumns = orderedColumns
      .filter((column) => visibleColumns.has(String(column.key)))
      .map((column) => ({
        ...column,
        ellipsis: column.ellipsis ?? true,
        render: (value: unknown, record: RecordType, index: number) => {
          const originalRender = column.render as ((value: unknown, record: RecordType, index: number) => React.ReactNode) | undefined
          const renderedValue = originalRender ? originalRender(value, record, index) : value
          const displayValue = column.uppercase && typeof renderedValue === 'string'
            ? renderedValue.toUpperCase()
            : renderedValue

          const openRecordTab = typeof column.openRecordTab === 'string' ? column.openRecordTab : undefined
          const openResource = column.openResource as ResourceColumn<RecordType>['openResource']
          const linkedResourceKey = typeof openResource?.resourceKey === 'function'
            ? openResource.resourceKey(record)
            : openResource?.resourceKey
          const linkedRowId = openResource?.rowId(record)
          if (openResource && linkedResourceKey && linkedRowId !== null && linkedRowId !== undefined && onOpenResource) {
            return (
              <Button
                type="link"
                size="small"
                onClick={(event) => {
                  event.stopPropagation()
                  onOpenResource(linkedResourceKey, linkedRowId)
                }}
                style={{ padding: 0, height: 'auto', fontFamily: 'inherit' }}
              >
                {displayValue as React.ReactNode}
              </Button>
            )
          }

          if ((column.openRecord || openRecordTab) && onRowClick) {
            return (
              <Button
                type="link"
                size="small"
                onClick={(event) => {
                  event.stopPropagation()
                  onRowClick(record, openRecordTab ? { tabKey: openRecordTab } : undefined)
                }}
                style={{ padding: 0, height: 'auto', fontFamily: 'inherit' }}
              >
                {displayValue as React.ReactNode}
              </Button>
            )
          }

          return displayValue as React.ReactNode
        },
      })) as ColumnsType<RecordType>

    return [
      ...visibleDataColumns,
      {
        key: '__actions',
        title: 'Actions',
        width: actionColumnWidth,
        fixed: 'right',
        align: 'center',
        render: (_value, record) => {
          const deleteAction = (
            <Popconfirm
              title="Delete record?"
              description="This action cannot be undone."
              okText="Delete"
              okButtonProps={{ danger: true }}
              onConfirm={(event) => {
                event?.stopPropagation()
                return handleDelete(record)
              }}
              onCancel={(event) => event?.stopPropagation()}
            >
              <Button
                danger
                size="small"
                type="text"
                icon={<DeleteOutlined />}
                onClick={(event) => event.stopPropagation()}
              />
            </Popconfirm>
          )
          return rowActions ? rowActions(record, { deleteAction }) : (
            <Space size={4} align="center" className="table-row-actions">
              {deleteAction}
            </Space>
          )
        },
      },
    ] as ColumnsType<RecordType>
  }, [actionColumnWidth, columnOrder, handleDelete, normalizedColumns, onOpenResource, onRowClick, rowActions, visibleColumns])

  const tableScrollX = useMemo(() => {
    const normalizedColumnMap = new Map(normalizedColumns.map((column) => [String(column.key), column]))
    const visibleDataWidth = columnOrder
      .map((key) => normalizedColumnMap.get(key))
      .filter((column): column is Record<string, unknown> => (
        column !== undefined && visibleColumns.has(String(column.key))
      ))
      .reduce((total, column) => total + columnScrollWidth(column), 0)

    return visibleDataWidth + actionColumnWidth + ROW_SELECTION_COLUMN_WIDTH
  }, [actionColumnWidth, columnOrder, normalizedColumns, visibleColumns])

  const orderedColumnSettings = useMemo(() => {
    const normalizedColumnMap = new Map(normalizedColumns.map((column) => [String(column.key), column]))
    return columnOrder
      .map((key) => normalizedColumnMap.get(key))
      .filter((column): column is Record<string, unknown> => Boolean(column))
  }, [columnOrder, normalizedColumns])

  const toggleColumn = (key: string) => {
    const column = normalizedColumns.find((item) => String(item.key) === key)
    if (!column || isLockedColumn(column)) return
    const next = new Set(visibleColumns)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    setVisibleColumns(next)
    saveColumnSettings(resolvedTableKey, next, columnOrder)
  }

  const sensors = useSensors(useSensor(PointerSensor, {
    activationConstraint: { distance: 4 },
  }))

  const handleColumnDragEnd = ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id) return
    const oldIndex = columnOrder.indexOf(String(active.id))
    const newIndex = columnOrder.indexOf(String(over.id))
    if (oldIndex === -1 || newIndex === -1) return
    const next = arrayMove(columnOrder, oldIndex, newIndex)
    setColumnOrder(next)
    saveColumnSettings(resolvedTableKey, visibleColumns, next)
  }

  const columnSettingsContent = (
    <div style={{ width: 260, maxHeight: 420, overflowY: 'auto' }}>
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleColumnDragEnd}>
        <SortableContext items={columnOrder} strategy={verticalListSortingStrategy}>
          {orderedColumnSettings.map((column) => (
            <SortableColumnSetting
              key={String(column.key)}
              columnKey={String(column.key)}
              title={String(column.title)}
              checked={visibleColumns.has(String(column.key))}
              locked={isLockedColumn(column)}
              onToggle={toggleColumn}
            />
          ))}
        </SortableContext>
      </DndContext>
    </div>
  )

  const handleChange: TableProps<RecordType>['onChange'] = (_, __, sorter) => {
    const activeSorter = Array.isArray(sorter) ? sorter[0] : sorter
    const field = activeSorter?.field
    if (!field || !activeSorter?.order) {
      setOrdering('')
      return
    }
    setOrdering(activeSorter.order === 'descend' ? `-${String(field)}` : String(field))
  }

  const handlePageChange = (nextPage: number, nextPageSize: number) => {
    setPage(nextPage)
    setPageSize(nextPageSize)
    localStorage.setItem(storageKey(resolvedTableKey, 'pageSize'), String(nextPageSize))
  }
  const hasActiveConditions = Boolean(
    search ||
    searchInput ||
    ordering ||
    Object.values(filterState.quick).some(hasFilterValue) ||
    filterState.advanced.some(isActiveAdvancedFilter),
  )
  const hasActiveFilters = Boolean(
    filterState.advanced.some(isActiveAdvancedFilter),
  )
  const clearAllConditions = () => {
    setSearchInput('')
    setSearch('')
    setOrdering('')
    setFilterState(emptyFilterState())
    setSavedFilterName('')
    setPage(1)
    setSelectedRowKeys([])
    setSelectedRows([])
    setTableResetKey((value) => value + 1)
  }
  const clearSelection = () => {
    setSelectedRowKeys([])
    setSelectedRows([])
  }
  const openFilterModal = () => {
    const rect = filterButtonRef.current?.getBoundingClientRect()
    if (rect) {
      const modalWidth = Math.min(TABLE_FILTER_MODAL_WIDTH, window.innerWidth - 32)
      const centeredLeft = rect.left + (rect.width / 2) - (modalWidth / 2)
      setFilterModalPosition({
        top: rect.bottom + 8,
        left: Math.min(Math.max(16, centeredLeft), window.innerWidth - modalWidth - 16),
      })
    }
    setFilterModalOpen(true)
  }
  const toolbarGap = dense ? 12 : 16
  const activeFilterCount = filterState.advanced.filter(isActiveAdvancedFilter).length
  const filterSummary = savedFilterName || (activeFilterCount > 0 ? `${activeFilterCount} filter(s)` : '')

  useLayoutEffect(() => {
    const container = containerRef.current
    const toolbar = toolbarRef.current
    if (!container || !toolbar) return

    const updateTableBodyHeight = () => {
      const tableHeaderHeight = dense ? 39 : 47
      const nextHeight = Math.max(
        MIN_TABLE_BODY_HEIGHT,
        Math.floor(container.clientHeight - toolbar.offsetHeight - toolbarGap - TABLE_BOTTOM_GAP - tableHeaderHeight),
      )
      setTableBodyHeight((current) => current === nextHeight ? current : nextHeight)
    }

    updateTableBodyHeight()
    const resizeObserver = new ResizeObserver(updateTableBodyHeight)
    resizeObserver.observe(container)
    resizeObserver.observe(toolbar)
    window.addEventListener('resize', updateTableBodyHeight)

    return () => {
      resizeObserver.disconnect()
      window.removeEventListener('resize', updateTableBodyHeight)
    }
  }, [dense, toolbarGap])

  return (
    <div ref={containerRef} style={{ display: 'flex', flexDirection: 'column', height: fillParent ? '100%' : 'calc(100vh - 96px)', minHeight: 0, overflow: 'hidden' }}>
      <div ref={toolbarRef} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, marginBottom: toolbarGap, flexShrink: 0 }}>
        <Space wrap align="center">
          <Input.Search
            placeholder={searchPlaceholder}
            value={searchInput}
            onChange={(event) => {
              const value = event.target.value
              setSearchInput(value)
              if (!value) {
                setSearch('')
                setPage(1)
              }
            }}
            onSearch={(value) => { setSearch(value); setPage(1) }}
            style={{ width: 360 }}
            allowClear
          />
          {filters?.map((filter) => (
            filter.valueType === 'tag' ? (
              <Select
                key={filter.key}
                mode="tags"
                placeholder={filter.label}
                allowClear
                style={{ width: filter.width || 180 }}
                options={filterOptions(filter)}
                value={filterState.quick[filter.key] || []}
                onChange={(value) => updateQuickFilter(filter.key, value)}
              />
            ) : (
              <Select
                key={filter.key}
                placeholder={filter.label}
                allowClear
                showSearch
                style={{ width: filter.width || 180 }}
                options={filterOptions(filter)}
                value={filterState.quick[filter.key] || undefined}
                onChange={(value) => updateQuickFilter(filter.key, value)}
              />
            )
          ))}
          <Tooltip title="Clear search, filters, and sorting">
            <Button icon={<ClearOutlined />} disabled={!hasActiveConditions} onClick={clearAllConditions} />
          </Tooltip>
          <Tooltip title="Filters">
            <Button ref={filterButtonRef} icon={<FilterOutlined />} type={hasActiveFilters ? 'primary' : 'default'} onClick={openFilterModal}>
              {filterSummary}
            </Button>
          </Tooltip>
          <Tooltip title="Column settings">
            <Popover trigger="click" placement="bottomRight" content={columnSettingsContent}>
              <Button icon={<SettingOutlined />} />
            </Popover>
          </Tooltip>
          <Button icon={<ReloadOutlined />} onClick={fetchData} />
          {actions}
          {selectedRowKeys.length > 0 && (
            <>
              <Divider type="vertical" style={{ alignSelf: 'center' }} />
              <Tooltip title="Clear selection">
                <Button icon={<CloseOutlined />} onClick={clearSelection} />
              </Tooltip>
              <Tooltip title="Delete selected">
                <Popconfirm
                  title={`Delete ${selectedRowKeys.length} selected record(s)?`}
                  description="This action cannot be undone."
                  okText="Delete"
                  okButtonProps={{ danger: true }}
                  onConfirm={handleBulkDelete}
                >
                  <Button danger icon={<DeleteOutlined />} />
                </Popconfirm>
              </Tooltip>
            </>
          )}
        </Space>
        <Pagination
          simple
          current={page}
          pageSize={pageSize}
          total={total}
          showSizeChanger
          pageSizeOptions={PAGE_SIZE_OPTIONS.map(String)}
          showTotal={(count) => `${count} row(s)`}
          size="small"
          onChange={handlePageChange}
          style={{ flexShrink: 0, display: 'flex', alignItems: 'center' }}
        />
      </div>
      <Table<RecordType>
        key={tableResetKey}
        className="asp-data-table"
        columns={antColumns}
        dataSource={data}
        rowKey={rowKey}
        loading={loading}
        size={dense ? 'small' : 'middle'}
        tableLayout="fixed"
        scroll={{ x: tableScrollX, y: tableBodyHeight }}
        rowSelection={{
          selectedRowKeys,
          fixed: true,
          getCheckboxProps: rowSelectionDisabled ? (record) => ({ disabled: rowSelectionDisabled(record) }) : undefined,
          onChange: (nextKeys, nextRows) => {
            setSelectedRowKeys(nextKeys)
            setSelectedRows(nextRows)
          },
        }}
        pagination={false}
        onChange={handleChange}
      />
      <TableFilterModal
        open={filterModalOpen}
        savedFiltersKey={resolvedSavedFiltersKey}
        advancedFilters={advancedFilters}
        metadata={metadata}
        value={filterState}
        position={filterModalPosition}
        onSavedFilterNameChange={setSavedFilterName}
        onChange={(next) => {
          setFilterState(next)
          setPage(1)
        }}
        onClose={() => setFilterModalOpen(false)}
      />
    </div>
  )
}
