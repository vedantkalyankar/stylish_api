from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'profile_picture', 'profile_picture_url', 'phone_number', 'is_verified', 'created_at', 'uploaded_at']
        read_only_fields = ['id','email','created_at', 'is_verified', 'prfile_picture_url' ]

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            return self.context['request'].build_absolute_url(obj.profile_picture_url)
        return None