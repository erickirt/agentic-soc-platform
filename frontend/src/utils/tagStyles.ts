import type {GetProps, TagProps, TagType} from 'antd'
import {typography} from './typography'

type CheckableTagGroupProps = GetProps<TagType['CheckableTagGroup']>


export const comfortableTagProps = {
  variant: 'outlined',
  classNames: {
    root: 'asp-comfortable-tag',
    content: 'asp-comfortable-tag-content',
  },
  styles: {
    root: {
      paddingInline: 8,
      paddingBlock: 0,
      borderRadius: 6,
      ...typography.tag,
    },
    content: {
      ...typography.tag,
    },
  },
} satisfies Pick<TagProps, 'variant' | 'classNames' | 'styles'>

export const comfortableCheckableTagGroupProps = {
  classNames: {
    root: 'asp-comfortable-checkable-tag-group',
    item: 'asp-comfortable-checkable-tag',
  },
  styles: {
    root: {
      gap: 6,
      flexWrap: 'nowrap',
    },
    item: {
      marginInlineEnd: 4,
      flexShrink: 0,
      paddingInline: 8,
      paddingBlock: 0,
      borderRadius: 6,
      fontSize: typography.tag.fontSize,
    },
  },
} satisfies Pick<CheckableTagGroupProps, 'classNames' | 'styles'>
