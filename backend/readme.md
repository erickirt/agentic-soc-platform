# ASP Backend

## Admin user maintenance

ASP admin users are Django superusers. They are created and maintained from the backend command line, not from the web UI. The web UI can assign only `user` or `viewer` roles.

Run commands from the repository root:

```powershell
cd backend
```

### Create an admin user

Use Django's `createsuperuser` command:

```powershell
.\.venv\Scripts\python.exe manage.py createsuperuser
```

Follow the prompts to enter username, email, and password. The created account logs in with **Platform** authentication.

### Reset an existing admin user's password

If you know the admin username, use:

```powershell
.\.venv\Scripts\python.exe manage.py changepassword <admin-username>
```

Example:

```powershell
.\.venv\Scripts\python.exe manage.py changepassword admin
```

### Find existing admin usernames

If you do not know the admin username:

```powershell
.\.venv\Scripts\python.exe manage.py shell -c "from apps.accounts.models import User; print('\n'.join(User.objects.filter(is_superuser=True).values_list('username', flat=True)))"
```

## Production processes

Use Nginx as the external entry point. Route normal Django HTTP/API/Admin traffic to Gunicorn and ASGI-only paths such as `/api/mcp` to Uvicorn.

```powershell
gunicorn asp.wsgi:application --bind 127.0.0.1:8000 --workers 2 --threads 4 --access-logfile - --error-logfile -
uvicorn asp.asgi:application --host 127.0.0.1 --port 8001 --access-log
python manage.py run_agentic_playbook_worker
python manage.py run_agentic_case_analysis_worker
python manage.py run_agentic_module_worker
python manage.py run_elk_action_worker
```

The production processes keep console logging enabled and write rotating gzip logs under `log`.
