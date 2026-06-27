import type {CSSProperties} from 'react'

const markdownBackground = 'transparent'
export const markdownBorderColor = '#303030'
export const markdownPreviewBackground = 'transparent'

export const markdownEditorThemeStyle = {
  '--md-editor-background-color': markdownBackground,
  '--md-editor-box-shadow-color': markdownBorderColor,
  '--color-canvas-default': markdownBackground,
  '--color-canvas-subtle': 'transparent',
  '--color-canvas-inset': markdownBackground,
  '--color-border-default': markdownBorderColor,
  '--color-border-muted': markdownBorderColor,
  '--color-fg-default': 'rgba(255,255,255,0.85)',
  '--color-fg-muted': 'rgba(255,255,255,0.55)',
  '--color-accent-fg': '#69b1ff',
  '--color-accent-muted': 'rgba(105,177,255,0.28)',
  '--color-neutral-muted': 'rgba(255,255,255,0.08)',
} as CSSProperties
