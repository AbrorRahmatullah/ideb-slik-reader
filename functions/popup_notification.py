from flask import url_for


def render_alert(message, redirect_url, username, fullname, email, role_access=None):
    return '''
    <script>
        alert("{}");
        window.location.href = "{}";
    </script>
    '''.format(message, url_for(redirect_url))