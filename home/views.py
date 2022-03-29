from django.shortcuts import render

# Create your views here.
def home(request):
    request.session['alpha'] = 'test'
    print(request.session.get('oidc_states', {}))
    template = 'home.html'
    template_vars = {'user':request.user, 'authenticated': request.user.is_authenticated}
    return render(request, template, template_vars)