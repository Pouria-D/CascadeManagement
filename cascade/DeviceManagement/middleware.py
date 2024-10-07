from django.urls import resolve
#from django.core.urlresolvers import resolve


class DisableCSRF(object):
    """
    Middleware for disabling CSRF in an specified app name.
    """
    def __init__(self, get_response):
        print ('****************** My first Middleware ********************')
        self.get_response = get_response

    def __call__(self, request):
        print('******************* Call method works :) ******************')
        current_url = resolve(request.path_info).url_name
        print(current_url)
        url_addr = "Remote"
        if url_addr in str(resolve(request.path_info)):
            setattr(request, '_dont_enforce_csrf_checks', True)
        else:
            pass # check CSRF token validation

        response = self.get_response(request)
        return response

    def process_request(self, request):
        """
        Preprocess the request.
        """
        url_addr = "Remote"
        if url_addr in str(resolve(request.path_info)):
            setattr(request, '_dont_enforce_csrf_checks', True)
        else:
            pass # check CSRF token validation

