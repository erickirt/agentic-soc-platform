from typing import List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from Lib.llmapi import BaseAgentState
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.SIEM.models import KeywordSearchInput, KeywordSearchOutput
from PLUGINS.SIEM.tools import SIEMToolKit
from PLUGINS.SIRP.sirpapi import Alert
from PLUGINS.SIRP.sirpmodel import AlertModel, PlaybookModel


class SearchKeyword(BaseModel):
    keyword: str = Field(description="Extract specific, high-fidelity strings valuable for full-text SIEM searches. Do not extract generic terms.")
    is_ioc: bool = Field(
        description="Set to true ONLY for public IPs, domains, URLs, and file hashes. Set to false for internal IPs, file paths, command lines, or general strings.")


class AlertExtraction(BaseModel):
    keywords: List[SearchKeyword] = Field(default_factory=list, description="List of extracted keywords and their IOC status.")
    start_time: str = Field(
        description="The start time for the log search, in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T06:00:00Z'")
    end_time: str = Field(description="The end time for the log search, in UTC ISO8601 format. Format: 'YYYY-MM-DDTHH:MM:SSZ'. Example: '2026-02-04T06:00:00Z'")


class AgentState(BaseAgentState):
    logs: List[KeywordSearchOutput] = []


class Playbook(LanggraphPlaybook):
    TYPE = "ALERT"  # Classification tag
    NAME = "Alert Summary Agent"  # PlaybookLoader name

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        def preprocess_node(state: AgentState):
            """Preprocess data"""
            alert = Alert.get(self.param_source_rowid)
            return {"alert": alert}

        # Define node
        def analyze_node(state: AgentState):
            """AI analyzes alert data"""
            alert: AlertModel = state.alert
            # Load system prompt
            system_prompt_template = self.load_system_prompt_template("extract_agent_system")

            system_message = system_prompt_template.format()

            # Construct few-shot examples
            few_shot_examples = [
            ]

            # Run
            llm_api = LLMAPI()

            llm = llm_api.get_model(tag="fast")

            # Construct message list
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=alert.model_dump_json())
            ]
            llm = llm.with_structured_output(AlertExtraction)
            alert_extraction: AlertExtraction = llm.invoke(messages)
            start_time = alert_extraction.start_time
            end_time = alert_extraction.end_time
            logs: List[KeywordSearchOutput] = []

            for keyword in alert_extraction.keywords:
                results = SIEMToolKit.keyword_search(
                    KeywordSearchInput(keyword=keyword.keyword, time_range_start=start_time, time_range_end=end_time))
                logs.extend(results)
            # response = LLMAPI.extract_think(response)  # Temporary solution for langchain chatollama bug
            return {"logs": logs}

        def output_node(state: AgentState):
            """Process analysis results"""

            self.agent_state = state
            return state

        # Compile graph
        workflow = StateGraph(AgentState)

        workflow.add_node("preprocess_node", preprocess_node)
        workflow.add_node("analyze_node", analyze_node)
        workflow.add_node("output_node", output_node)

        workflow.set_entry_point("preprocess_node")
        workflow.add_edge("preprocess_node", "analyze_node")
        workflow.add_edge("analyze_node", "output_node")
        workflow.set_finish_point("output_node")
        model = AlertModel()
        self.agent_state = AgentState()
        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True

    def run(self):
        self.run_graph()
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_worksheet='alert', source_rowid='f7a4b955-c511-4528-9095-4559bac5e6b7')
    module = Playbook()
    module._playbook_model = model

    module.run()
