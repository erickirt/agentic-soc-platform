import React from 'react'
import ReactDOM from 'react-dom/client'
import {BrowserRouter} from 'react-router-dom'
import {ConfigProvider} from 'antd'
import App from './App'
import themeConfig from './theme'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ConfigProvider theme={themeConfig}>
        <App />
      </ConfigProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
