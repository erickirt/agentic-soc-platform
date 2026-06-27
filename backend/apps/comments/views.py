from django.contrib.contenttypes.models import ContentType
from rest_framework import viewsets, permissions
from rest_framework.exceptions import PermissionDenied

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from .models import Comment
from .serializers import CommentSerializer


class CommentViewSet(viewsets.ModelViewSet):
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]

    def get_queryset(self):
        qs = Comment.objects.select_related("author", "content_type", "parent", "parent__author").prefetch_related(
            "mentions",
            "attachments",
        )
        ct = self.request.query_params.get("content_type")
        oid = self.request.query_params.get("object_id")
        if ct and oid:
            try:
                ct_model = ContentType.objects.get(model=ct)
                qs = qs.filter(content_type=ct_model, object_id=oid)
            except ContentType.DoesNotExist:
                qs = qs.none()
        return qs.order_by("-created_at")

    def perform_destroy(self, instance):
        if instance.author_id != self.request.user.id:
            raise PermissionDenied("You can only delete your own comments.")
        instance.delete()
