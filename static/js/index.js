document.getElementById("mostrarSenha").addEventListener("click", function() {
    var senhaInput = document.getElementById("senha");
    var imgVerOcultar = document.querySelector(".verocultar")
    if (senhaInput.type === "password") {
        senhaInput.type = "text";
        imgVerOcultar.src = "../static/image/ver-senha.png"
    } else {
        senhaInput.type = "password";
        imgVerOcultar.src = "../static/image/oculta-senha.png"
    }
});
history.pushState(null, null, 'pagina_nao_autenticada');
window.addEventListener('popstate', function () {
    history.pushState(null, null, 'pagina_nao_autenticada');
});
