from django.views.decorators.http import require_POST
from django.http import JsonResponse

@require_POST
def transfer(request):
    do_transfer(request.user, request.POST["to"], request.POST["amount"])
    return JsonResponse({"ok": True})
