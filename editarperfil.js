document.addEventListener('DOMContentLoaded', async () => {
    const userId = localStorage.getItem('userId'); 
    if (userId) {
        const response = await fetch(`http://localhost:3000/auth/user/${userId}`); 
        if (response.ok) {
            const user = await response.json();
           
            document.getElementById('name').value = user.login; 
            document.getElementById('email').value = user.email; 
        } else {
            console.error('Erro ao carregar os dados do usuário:', response.statusText);
        }
    } else {
        console.warn('Usuário não autenticado');
    }
});

document.getElementById('editForm').addEventListener('submit', async function(event) {
    event.preventDefault(); 

    const userId = localStorage.getItem('userId'); 
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('new-password').value;

    const response = await fetch('http://localhost:3000/auth/update', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id: userId, name, email, password }) 
    });

    const data = await response.json();
    if (response.ok) {
        
        const notification = document.getElementById('notification');
        notification.style.display = 'block'; 
        notification.textContent = 'As alterações foram salvas com sucesso!'; 
        setTimeout(() => {
            notification.style.display = 'none'; 
        }, 3000);
        
        // Redireciona após sucesso
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 3000);
    } else {
        alert(data.error); 
    }
});


document.getElementById('deleteProfile').addEventListener('click', function() {
    const deleteConfirmation = document.getElementById('deleteConfirmation');
    deleteConfirmation.style.display = 'block'; 
});


document.getElementById('confirmDelete').addEventListener('click', async function() {
    const userId = localStorage.getItem('userId'); 

    const response = await fetch(`http://localhost:3000/auth/delete/${userId}`, {
        method: 'DELETE'
    });

    const data = await response.json();
    if (response.ok) {
        
        const deleteNotification = document.getElementById('deleteNotification');
        deleteNotification.style.display = 'block'; 
        deleteNotification.textContent = 'Perfil excluído com sucesso!';

        setTimeout(() => {
            deleteNotification.style.display = 'none'; 
            localStorage.removeItem('userId'); 
            window.location.href = 'index.html'; 
        }, 4000); 
    } else {
        alert(data.error); 
    }
});

document.getElementById('cancelDelete').addEventListener('click', function() {
    const deleteConfirmation = document.getElementById('deleteConfirmation');
    deleteConfirmation.style.display = 'none'; 
});
