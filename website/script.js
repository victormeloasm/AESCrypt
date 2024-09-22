// Exemplo de JavaScript para adicionar interatividade
document.addEventListener("DOMContentLoaded", () => {
    // Adiciona um evento ao clicar nos links de download
    const downloadLinks = document.querySelectorAll('a[href^="https://github.com/victormeloasm/AESCrypt/releases"]');
    downloadLinks.forEach(link => {
        link.addEventListener('click', (event) => {
            alert('Você está prestes a baixar o AESCrypt!');
        });
    });
});
