from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

@csrf_exempt
def transfer(request):
    do_transfer(request.user, request.POST["to"], request.POST["amount"])
    return JsonResponse({"ok": True})
