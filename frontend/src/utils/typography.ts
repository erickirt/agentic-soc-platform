import type {CSSProperties} from 'react'

export const fontFamilySans = [
  '-apple-system',
  'BlinkMacSystemFont',
  "'Segoe UI'",
  'Roboto',
  "'Helvetica Neue'",
  'Arial',
  "'Noto Sans'",
  'sans-serif',
  "'Apple Color Emoji'",
  "'Segoe UI Emoji'",
  "'Segoe UI Symbol'",
  "'Noto Color Emoji'",
].join(', ')

export const fontFamilyMono = [
  "'JetBrains Mono'",
  "'SFMono-Regular'",
  'Consolas',
  "'Liberation Mono'",
  'Menlo',
  'Monaco',
  "'Courier New'",
  'monospace',
].join(', ')

export const typography = {
  displayTitle: { fontSize: 24, fontWeight: 600, lineHeight: 1.25 },
  detailTitle: { fontSize: 18, fontWeight: 600, lineHeight: 1.2 },
  sectionHeading: { fontSize: 16, fontWeight: 600, lineHeight: '24px' },
  sectionTitle: { fontSize: 14, fontWeight: 600, lineHeight: '22px' },
  fieldLabel: { fontSize: 14, fontWeight: 500, lineHeight: '22px' },
  body: { fontSize: 14, fontWeight: 400, lineHeight: '22px' },
  secondary: { fontSize: 12, fontWeight: 400, lineHeight: '20px' },
  compact: { fontSize: 12, fontWeight: 400, lineHeight: 1.2 },
  tag: { fontSize: 13, lineHeight: '20px' },
  code: { fontSize: 13, lineHeight: '20px', fontFamily: fontFamilyMono },
} satisfies Record<string, CSSProperties>

export const monoTextStyle = {
  fontFamily: fontFamilyMono,
  fontVariantNumeric: 'tabular-nums',
} satisfies CSSProperties

export const tabularNumbersStyle = {
  fontVariantNumeric: 'tabular-nums',
} satisfies CSSProperties
