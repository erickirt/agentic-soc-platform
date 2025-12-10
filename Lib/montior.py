# -*- coding: utf-8 -*-
# @File  : montior.py
# @Date  : 2021/2/25
# @Desc  :


import importlib

from apscheduler.schedulers.background import BackgroundScheduler
from django.contrib.auth.models import User

from Automation.Handle.playbook import Playbook
from Lib.apsmodule import aps_module
from Lib.baseplaybook import BasePlaybook
from Lib.engine import Engine
from Lib.log import logger
from Lib.xcache import Xcache
from PLUGINS.Redis.CONFIG import REDIS_STREAM_STORE_DAYS
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIRP.CONFIG import ASP_REST_API_TOKEN
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook


class MainMonitor(object):
    BotScheduler: BackgroundScheduler
    MainScheduler: BackgroundScheduler
    HeartBeatScheduler: BackgroundScheduler
    WebModuleScheduler: BackgroundScheduler
    _background_threads = {}

    def __init__(self):
        self.engine = Engine()
        self.redis_stream_api = RedisStreamAPI()
        self.MainScheduler = BackgroundScheduler(timezone='Asia/Shanghai')

    def start(self):
        logger.info("启动后台服务")

        # add api user
        logger.info("写入ASP_TOKEN到缓存")
        api_usr = User()
        api_usr.username = "api_token"
        api_usr.is_active = True
        Xcache.set_token_user(ASP_REST_API_TOKEN, api_usr, None)

        logger.info("加载剧本配置信息")
        Playbook.load_all_module_config()

        # self.MainScheduler.add_job(func=self.subscribe_clean_thread,
        #                            max_instances=1,
        #                            trigger='interval',
        #                            hours=1,
        #                            id='subscribe_clean_thread')
        self.MainScheduler.add_job(func=self.subscribe_pending_playbook,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=3,
                                   id='subscribe_clean_thread')
        self.MainScheduler.start()

        # engine
        self.engine.start()
        logger.info("后台服务启动成功")

    def subscribe_clean_thread(self):
        self.redis_stream_api.clean_redis_stream(max_age_days=REDIS_STREAM_STORE_DAYS)

    def subscribe_pending_playbook(self):
        records = SIRPPlaybook.get_pending_playbooks()
        print(records)

        for one_record in records:
            name = one_record.get("name")
            type = one_record.get("type")
            row_id = one_record.get("rowId")
            module_config = Xcache.get_module_config_by_name_and_type(type, name)
            if module_config is None:
                Playbook.load_all_module_config()
                module_config = Xcache.get_module_config_by_name_and_type(type, name)
            if module_config is None:
                logger.error(f"Playbook module config not found: {type} - {name}")
                fields = [
                    {"id": "job_status", "value": "Failed"},
                    {"id": "remark", "value": f"Playbook module config not found: {type} - {name}"},
                ]
                SIRPPlaybook.update(row_id, fields)
                continue
            load_path = module_config.get("load_path")
            if one_record.get("user"):
                user = one_record.get("user")[0].get("fullname")
            else:
                user = None
            params = {
                "rowId": row_id,
                "source_worksheet": one_record.get("type").lower(),
                "source_rowid": one_record.get("source_rowid"),
                "user_input": one_record.get("user_input"),
                "user": user,
            }
            try:
                class_intent = importlib.import_module(load_path)
                playbook_intent: BasePlaybook = class_intent.Playbook()
                playbook_intent._params = params
            except Exception as E:
                logger.exception(E)
                fields = [
                    {"id": "job_status", "value": "Failed"},
                    {"id": "remark", "value": f"{E}"},
                ]
                SIRPPlaybook.update(row_id, fields)
                continue

            job_id = aps_module.putin_post_python_module_queue(playbook_intent)
            if job_id:
                logger.info(f"Create playbook job success: {job_id}")
                fields = [
                    {"id": "job_status", "value": "Running"},
                    {"id": "job_id", "value": job_id},
                ]
                SIRPPlaybook.update(row_id, fields)
            else:
                fields = [
                    {"id": "job_status", "value": "Failed"},
                    {"id": "remark", "value": f"Failed to create playbook job."},
                ]
                SIRPPlaybook.update(row_id, fields)
