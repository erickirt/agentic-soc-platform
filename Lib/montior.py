# -*- coding: utf-8 -*-

import importlib
import threading
import time
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler
from django.contrib.auth.models import User

from Lib.apsmodule import aps_module
from Lib.baseplaybook import BasePlaybook
from Lib.engine import Engine
from Lib.log import logger
from Lib.playbookloader import PlaybookLoader
from Lib.xcache import Xcache
from PLUGINS.Embeddings.embeddings_qdrant import embedding_api_singleton_qdrant
from PLUGINS.Mem0.CONFIG import USE as MEM_ZERO_USE
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI
from PLUGINS.SIRP.sirpapi import Playbook as SIRPPlaybook, Knowledge, KnowledgeAction
from PLUGINS.SIRP.sirptype import PlaybookJobStatus

if MEM_ZERO_USE:
    from PLUGINS.Mem0.mem_zero import mem_zero_singleton

ASP_REST_API_TOKEN = "nocoly_token_for_playbook"


class MainMonitor(object):
    MainScheduler: BackgroundScheduler
    _background_threads = {}

    def __init__(self):
        self.engine = Engine()
        self.redis_stream_api = RedisStreamAPI()
        self.MainScheduler = BackgroundScheduler(timezone='Asia/Shanghai')

    @staticmethod
    def run_task_in_loop(task_func: Callable, task_name: str, retry_interval: int = 5, exec_interval: int = None):
        """
        Run a task function in an infinite loop with error handling

        Args:
            task_func: The function to run
            task_name: Name of the task for logging
            retry_interval: Seconds to wait between retries on error
            exec_interval: Seconds to wait between executions (defaults to retry_interval if None)
        """
        # If exec_interval is not specified, use retry_interval
        if exec_interval is None:
            exec_interval = retry_interval

        while True:
            try:
                task_func()
                # Wait for the specified execution interval before running again
                time.sleep(exec_interval)
            except Exception as e:
                logger.error(f"Error in {task_name}")
                logger.exception(e)
                time.sleep(retry_interval)

    def start_background_task(self, task_func: Callable, task_name: str, retry_interval: int = 5, exec_interval: int = None):
        """
        Start a background task in a separate thread

        Args:
            task_func: The function to run
            task_name: Name of the task for logging
            retry_interval: Seconds to wait between retries on error
            exec_interval: Seconds to wait between executions (defaults to retry_interval if None)
        """
        thread = threading.Thread(
            target=self.run_task_in_loop,
            args=(task_func, task_name, retry_interval, exec_interval),
            daemon=True,
            name=task_name
        )
        self._background_threads[task_name] = thread
        thread.start()
        logger.info(f"Started background task: {task_name}")

    def start(self):
        logger.info("Starting background services...")

        # add api user
        logger.info("Write ASP_TOKEN to cache")
        api_usr = User()
        api_usr.username = "api_token"
        api_usr.is_active = True

        Xcache.set_token_user(ASP_REST_API_TOKEN, api_usr, None)

        logger.info("Load PlaybookLoader module config")
        PlaybookLoader.load_all_playbook_config()

        delay_time = 3

        # Start background tasks
        self.start_background_task(self.subscribe_pending_playbook, "subscribe_pending_playbook", delay_time)
        self.start_background_task(self.subscribe_knowledge_action, "subscribe_knowledge_action", delay_time)

        # engine
        self.engine.start()
        logger.info("Background services started.")

    @staticmethod
    def subscribe_pending_playbook():
        models = SIRPPlaybook.list_pending_playbooks()

        for model in models:
            module_config = Xcache.get_module_config_by_name_and_type(model.type, model.name)
            if module_config is None:
                PlaybookLoader.load_all_playbook_config()  # try again
                module_config = Xcache.get_module_config_by_name_and_type(model.type, model.name)
            if module_config is None:
                logger.error(f"PlaybookLoader module config not found: {model.type} - {model.name}")
                model.job_status = PlaybookJobStatus.FAILED
                model.remark = f"PlaybookLoader module config not found: {model.type} - {model.name}"
                SIRPPlaybook.update_or_create(model)
                continue

            load_path = module_config.get("load_path")

            try:
                class_intent = importlib.import_module(load_path)
                playbook_intent: BasePlaybook = class_intent.Playbook()
                playbook_intent._playbook_model = model
            except Exception as E:
                logger.exception(E)
                model.job_status = PlaybookJobStatus.FAILED
                model.remark = str(E)
                SIRPPlaybook.update_or_create(model)
                continue

            job_id = aps_module.putin_post_python_module_queue(playbook_intent)
            if not job_id:
                model.job_status = PlaybookJobStatus.FAILED
                model.remark = "Failed to create playbook job."
                SIRPPlaybook.update_or_create(model)
                continue
            else:
                logger.info(f"Create playbook job success: {job_id}")
                model.job_status = PlaybookJobStatus.RUNNING
                model.job_id = job_id
                SIRPPlaybook.update_or_create(model)

    @staticmethod
    def subscribe_knowledge_action():
        records = Knowledge.get_undone_actions()
        if records:
            for one_record in records:
                action = one_record.get("action")
                using = one_record.get("using")
                row_id = one_record.get("rowid")
                title = one_record.get("title")
                body = one_record.get("body")

                payload_content = f"# {title}\n\n{body}"

                if action == KnowledgeAction.STORE:
                    logger.info(f"Knowledge storing,rowid: {row_id}")
                    try:
                        result = embedding_api_singleton_qdrant.add_document(Knowledge.COLLECTION_NAME, row_id, payload_content, {"rowid": row_id})
                    except Exception as E:
                        logger.exception(E)

                    try:
                        if MEM_ZERO_USE:
                            result = mem_zero_singleton.add_mem(user_id=Knowledge.COLLECTION_NAME, run_id=row_id, content=payload_content,
                                                                metadata={"rowid": row_id})
                    except Exception as E:
                        logger.exception(E)

                    action = KnowledgeAction.DONE
                    using = 1
                    logger.info(f"Knowledge stored,rowid: {row_id}")
                elif action == KnowledgeAction.REMOVE:
                    logger.info(f"Knowledge removing,rowid: {row_id}")
                    try:
                        result = embedding_api_singleton_qdrant.delete_document(Knowledge.COLLECTION_NAME, row_id)
                    except Exception as E:
                        logger.exception(E)

                    try:
                        if MEM_ZERO_USE:
                            result = mem_zero_singleton.delete_mem(user_id=Knowledge.COLLECTION_NAME, run_id=row_id)
                    except Exception as E:
                        logger.exception(E)

                    action = KnowledgeAction.DONE
                    using = 0
                    logger.info(f"Knowledge removed,rowid: {row_id}")
                else:
                    logger.error(f"Unknown knowledge action: {action}")
                    continue

                # update status to Done
                row_id = Knowledge.update_action_and_using(row_id, action, using)
