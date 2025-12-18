from typing import Annotated, List, Literal, Any

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from Lib.baseplaybook import LanggraphPlaybook
from PLUGINS.LLM.llmapi import LLMAPI
# Modify the following functions to the actual CMDB API
from PLUGINS.Mock.CMDB import get_ci_context_tool, fuzzy_search_ci_tool, get_cis_by_software_tool, get_cis_by_port_tool, get_cis_by_service_tool, \
    get_cis_by_user_tool


class CMDBAgent(object):

    @staticmethod
    def cmdb_query_asset(
            query: Annotated[str, "The CMDB query in natural language (e.g., 'Find asset with IP 10.10.10.10')"]
    ) -> Annotated[str, "A JSON containing asset details"]:
        """
        Query internal asset information from CMDB.
        """
        # You can also use the simpler create_agent method to create an agent
        # result = cmdb_query(query)
        # return result

        agent = GraphAgent()
        result = agent.cmdb_query(query)
        return result


AGENT_NODE = "AGENT_NODE"
TOOL_NODE = "TOOL_NODE"


class AgentState(BaseModel):
    messages: Annotated[List[Any], add_messages] = Field(default_factory=list)


# Use langgraph to create a CMDB query agent for finer-grained control
class GraphAgent(LanggraphPlaybook):

    def __init__(self):
        super().__init__()  # do not delete this code
        self.init()

    def init(self):
        tools = [
            get_ci_context_tool,
            fuzzy_search_ci_tool,
            get_cis_by_software_tool,
            get_cis_by_port_tool,
            get_cis_by_service_tool,
            get_cis_by_user_tool,
        ]

        tool_node = ToolNode(tools, name=TOOL_NODE)

        def route_after_agent(state: AgentState) -> Literal[TOOL_NODE, END]:
            messages = state.messages
            last_message = messages[-1]
            if last_message.tool_calls:
                return TOOL_NODE
            return END

        def agent_node(state: AgentState):
            system_prompt_template = self.load_system_prompt_template(f"system")
            system_message = system_prompt_template.format()

            messages = [
                system_message,
                *state.messages
            ]

            llm_api = LLMAPI()

            llm = llm_api.get_model(tag=["fast", "function_calling"])

            llm_with_tools = llm.bind_tools(tools)
            response = llm_with_tools.invoke(messages)

            return {"messages": [response]}

        workflow = StateGraph(AgentState)

        workflow.add_node(AGENT_NODE, agent_node)
        workflow.add_node(TOOL_NODE, tool_node)

        workflow.set_entry_point(AGENT_NODE)
        workflow.add_conditional_edges(AGENT_NODE, route_after_agent)
        workflow.add_edge(TOOL_NODE, AGENT_NODE)

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())

    def cmdb_query(self, query):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        self.agent_state = AgentState(messages=[HumanMessage(content=query)])
        response = self.graph.invoke(self.agent_state, config)
        return response['messages'][-1].content


# Use the create_agent method to create a CMDB query agent for a simpler implementation
def cmdb_query(
        query: Annotated[str, "The CMDB query in natural language (e.g., 'Find asset with IP 10.10.10.10')"]
) -> Annotated[str, "The query result in JSON format"]:
    """
    Query internal asset information from CMDB using natural language.
    """
    llm_api = LLMAPI()

    llm = llm_api.get_model(tag=["fast", "function_calling"])

    CMDB_AGENT_TOOLS = [
        get_ci_context_tool,
        fuzzy_search_ci_tool,
        get_cis_by_software_tool,
        get_cis_by_port_tool,
        get_cis_by_service_tool,
        get_cis_by_user_tool,
    ]
    agent = create_agent(
        model=llm,
        tools=CMDB_AGENT_TOOLS,
        system_prompt="You are a CMDB query assistant. You can call appropriate CMDB tools to query based on the user's natural language query request and return the results in JSON format.",
    )

    response = agent.invoke({"messages": [HumanMessage(content=query)]})

    result = response['messages'][-1].content
    return result


if __name__ == "__main__":
    query = "Find asset information for IP address 192.168.10.5"

    # result = cmdb_query(query)

    agent = GraphAgent()
    result = agent.cmdb_query(query)
    print(result)
