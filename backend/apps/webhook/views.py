from pydantic import ValidationError
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.webhook.service import (
    WebhookRedisError,
    handle_kibana_webhook,
    handle_splunk_webhook,
)


class SplunkWebhookView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            result = handle_splunk_webhook(request.data)
        except (ValidationError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except WebhookRedisError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(result.model_dump(), status=status.HTTP_200_OK)


class KibanaWebhookView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            result = handle_kibana_webhook(request.data)
        except (ValidationError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except WebhookRedisError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(result.model_dump(), status=status.HTTP_200_OK)
