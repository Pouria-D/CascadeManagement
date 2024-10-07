from django.urls import resolve

class MyMiddleware:
    def __init__(self, get_response):
        print ('****************** My first Middleware ********************')
        self.get_response = get_response

    def __call__(self, request):
        print('******************* Call method works :) ******************')
        current_url = resolve(request.path_info).url_name
        print(current_url)
        response = self.get_response(request)
        return response


