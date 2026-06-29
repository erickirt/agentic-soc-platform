import React from 'react'
import ReactDOM from 'react-dom/client'
import {BrowserRouter} from 'react-router-dom'
import {App as AntApp, ConfigProvider} from 'antd'
import App from './App'
import themeConfig from './theme'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ConfigProvider theme={themeConfig}>
        <AntApp>
          <App />
        </AntApp>
      </ConfigProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
