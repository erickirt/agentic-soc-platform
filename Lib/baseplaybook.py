import json

from langchain_core.messages import (
    BaseMessage,
    SystemMessage,
    HumanMessage,
    AIMessage,
    ToolMessage
)
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from Lib.baseapi import BaseAPI
from Lib.llmapi import AgentState
from Lib.log import logger
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook, Notice
from PLUGINS.SIRP.sirpapi import PlaybookMessage, PlaybookStatusType


class BasePlaybook(BaseAPI):
    RUN_AS_JOB = True  # 是否作为后台任务运行
    TYPE = None
    NAME = None

    def __init__(self):
        super().__init__()
        self._params = {}
        self.logger = logger

    def param(self, key, default=None):
        return self._params.get(key, default)

    # 定义内部参数
    @property
    def param_rowid(self):
        return self.param("rowId")

    @property
    def param_source_rowid(self):
        return self.param("source_rowid")

    @property
    def param_source_worksheet(self):
        return self.param("source_worksheet")

    @property
    def param_user(self):
        return self.param("user")

    @property
    def param_user_input(self):
        return self.param("user_input")

    def update_playbook(self, status: PlaybookStatusType, remark: str):
        rowid = SIRPPlaybook.update_status_and_remark(self.param_rowid, status, remark)
        return rowid

    def send_notice(self, title: str, body: str):
        result = Notice.send(self.param_user, title, body)
        return result


class LanggraphPlaybook(BasePlaybook):
    def __init__(self):
        super().__init__()
        self.graph: CompiledStateGraph = None
        self.agent_state = None

    @staticmethod
    def get_checkpointer():
        checkpointer = MemorySaver()
        return checkpointer

    def add_message_to_playbook(self, message: BaseMessage | BaseModel, playbook_rowid=None, node=None):
        if playbook_rowid is None:
            playbook_rowid = self.param_rowid

        if isinstance(message, SystemMessage):
            fields = [
                {"id": "type", "value": "SystemMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": message.content},
                {"id": "json", "value": None},
            ]
        elif isinstance(message, HumanMessage):
            fields = [
                {"id": "type", "value": "HumanMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": message.content},
                {"id": "json", "value": None},
            ]
        elif isinstance(message, AIMessage):
            if hasattr(message, 'tool_calls') and message.tool_calls:
                fields = [
                    {"id": "type", "value": "AIMessage"},
                    {"id": "node", "value": node},
                    {"id": "playbook_rowid", "value": playbook_rowid},
                    {"id": "content", "value": message.content},
                    {"id": "json", "value": json.dumps(message.tool_calls)},
                ]
            else:
                fields = [
                    {"id": "type", "value": "AIMessage"},
                    {"id": "node", "value": node},
                    {"id": "playbook_rowid", "value": playbook_rowid},
                    {"id": "content", "value": message.content},
                    {"id": "json", "value": None},
                ]
        elif isinstance(message, ToolMessage):
            try:
                json_data = {"name": message.name, "tool_call_id": message.tool_call_id, "result": json.loads(message.content)}
            except json.decoder.JSONDecodeError:
                json_data = {"name": message.name, "tool_call_id": message.tool_call_id, "result": message.content}

            fields = [
                {"id": "type", "value": "ToolMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "json", "value": json.dumps(json_data)},
            ]
        elif isinstance(message, BaseModel):
            fields = [
                {"id": "type", "value": "AIMessage"},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": None},
                {"id": "json", "value": message.model_dump_json()},
            ]
        else:
            fields = [
                {"id": "role", "value": message.type},
                {"id": "node", "value": node},
                {"id": "playbook_rowid", "value": playbook_rowid},
                {"id": "content", "value": message.content},
                {"id": "json", "value": None},
            ]
        row_id = PlaybookMessage.create(fields)
        return row_id

    # langgraph interface
    def run_graph(self):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        if self.agent_state is None:
            self.agent_state = AgentState()
        for event in self.graph.stream(self.agent_state, config, stream_mode="values"):
            self.logger.debug(event)

    def run(self):
        self.run_graph()
        return self.agent_state
