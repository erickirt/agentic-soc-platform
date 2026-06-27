import type {CSSProperties} from 'react'
import {useLayoutEffect, useMemo, useRef, useState} from 'react'
import {Tag, Tooltip} from 'antd'
import {comfortableTagProps} from '../utils/tagStyles'
import {emptyValueNode} from '../utils/recordDisplay'

interface OverflowTagsProps {
  items: unknown
  color?: string
}

const TAG_GAP = 4
const tagStyle: CSSProperties = { marginInlineEnd: 0, flexShrink: 0 }
const tooltipContentStyle: CSSProperties = {
  display: 'inline-flex',
  flexWrap: 'wrap',
  gap: TAG_GAP,
  maxWidth: 360,
}
const tooltipStyles = {
  root: {
    maxWidth: 400,
  },
  container: {
    padding: 0,
    background: 'transparent',
    boxShadow: 'none',
  },
}
const containerStyle: CSSProperties = {
  position: 'relative',
  display: 'inline-flex',
  alignItems: 'center',
  gap: TAG_GAP,
  width: '100%',
  maxWidth: '100%',
  minWidth: 0,
  overflow: 'hidden',
  whiteSpace: 'nowrap',
  verticalAlign: 'middle',
}
const measureStyle: CSSProperties = {
  position: 'absolute',
  left: 0,
  top: 0,
  display: 'inline-flex',
  alignItems: 'center',
  gap: TAG_GAP,
  visibility: 'hidden',
  pointerEvents: 'none',
  whiteSpace: 'nowrap',
}

function totalWidth(widths: number[]) {
  if (!widths.length) return 0
  return widths.reduce((total, width) => total + width, 0) + TAG_GAP * (widths.length - 1)
}

function visibleTagCount(values: string[], availableWidth: number, tagWidths: number[], indicatorWidths: Map<number, number>) {
  if (!values.length || availableWidth <= 0) return values.length
  if (totalWidth(tagWidths) <= availableWidth) return values.length

  for (let count = values.length - 1; count >= 0; count -= 1) {
    const hiddenCount = values.length - count
    const indicatorWidth = indicatorWidths.get(hiddenCount) ?? 0
    const widths = count > 0 ? [...tagWidths.slice(0, count), indicatorWidth] : [indicatorWidth]
    if (totalWidth(widths) <= availableWidth) return count
  }

  return 0
}

export default function OverflowTags({ items, color = 'blue' }: OverflowTagsProps) {
  const values = useMemo(() => Array.isArray(items) ? items.map((item) => String(item)) : [], [items])
  const containerRef = useRef<HTMLSpanElement>(null)
  const measureRef = useRef<HTMLSpanElement>(null)
  const [visibleCount, setVisibleCount] = useState(values.length)

  useLayoutEffect(() => {
    const updateVisibleCount = () => {
      const container = containerRef.current
      const measure = measureRef.current
      if (!container || !measure) return

      const availableWidth = container.getBoundingClientRect().width
      const tagWidths = Array.from(measure.querySelectorAll<HTMLElement>('[data-tag-index]'))
        .sort((left, right) => Number(left.dataset.tagIndex) - Number(right.dataset.tagIndex))
        .map((node) => node.getBoundingClientRect().width)
      const indicatorWidths = new Map<number, number>()
      measure.querySelectorAll<HTMLElement>('[data-hidden-count]').forEach((node) => {
        indicatorWidths.set(Number(node.dataset.hiddenCount), node.getBoundingClientRect().width)
      })

      const nextVisibleCount = visibleTagCount(values, availableWidth, tagWidths, indicatorWidths)
      setVisibleCount((previous) => previous === nextVisibleCount ? previous : nextVisibleCount)
    }

    updateVisibleCount()
    const container = containerRef.current
    if (!container) return undefined

    const resizeObserver = new ResizeObserver(updateVisibleCount)
    resizeObserver.observe(container)
    return () => resizeObserver.disconnect()
  }, [values])

  if (!values.length) {
    return emptyValueNode()
  }

  const safeVisibleCount = Math.min(visibleCount, values.length)
  const visible = values.slice(0, safeVisibleCount)
  const hidden = values.slice(safeVisibleCount)
  const hiddenTitle = (
    <span style={tooltipContentStyle}>
      {hidden.map((item, index) => (
        <Tag {...comfortableTagProps} key={`hidden-${item}-${index}`} color={color} style={tagStyle}>{item}</Tag>
      ))}
    </span>
  )

  return (
    <span ref={containerRef} style={containerStyle}>
      {visible.map((item, index) => (
        <Tag {...comfortableTagProps} key={`${item}-${index}`} color={color} style={tagStyle}>{item}</Tag>
      ))}
      {hidden.length > 0 && (
        <Tooltip arrow={false} placement="top" title={hiddenTitle} styles={tooltipStyles}>
          <Tag {...comfortableTagProps} color={color} style={tagStyle}>+{hidden.length}</Tag>
        </Tooltip>
      )}
      <span ref={measureRef} aria-hidden="true" style={measureStyle}>
        {values.map((item, index) => (
          <Tag {...comfortableTagProps} key={`measure-${item}-${index}`} data-tag-index={index} color={color} style={tagStyle}>{item}</Tag>
        ))}
        {values.map((_item, index) => {
          const hiddenCount = index + 1
          return (
            <Tag {...comfortableTagProps} key={`measure-more-${hiddenCount}`} data-hidden-count={hiddenCount} color={color} style={tagStyle}>
              +{hiddenCount}
            </Tag>
          )
        })}
      </span>
    </span>
  )
}
