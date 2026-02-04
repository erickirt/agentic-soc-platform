from models import AdaptiveQueryInput, SchemaExplorerInput
from tools import SIEMToolKit


def main():
    toolkit = SIEMToolKit()
    all = toolkit.explore_schema()
    print(all)
    all = toolkit.explore_schema(SchemaExplorerInput(target_index="siem-aws-cloudtrail"))
    print(all)

    query_input = AdaptiveQueryInput(
        index_name="siem-aws-cloudtrail",
        time_field="@timestamp",  # 这里可以改成任意 Date 类型字段，如 "event.created"
        time_range_start="2026-02-05T02:41:00Z",
        time_range_end="2026-02-05T02:41:10Z",
        filters={"event.outcome": "success", "source.ip": "45.33.22.11", "user.name": "github-actions-role"}
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Using time field: {query_input.time_field}")
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")

    query_input = AdaptiveQueryInput(
        index_name="siem-network-traffic",
        time_range_start="2026-02-05T02:40:00Z",
        time_range_end="2026-02-05T02:45:10Z",
        filters={"event.dataset": "network", "destination.ip": "104.21.11.22"}
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Using time field: {query_input.time_field}")
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")


if __name__ == "__main__":
    main()
