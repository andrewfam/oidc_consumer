from django.db import models

# Create your models here.
class StateStore(models.Model):
	key  = models.CharField('Session Key', max_length=100)
	data = models.TextField()