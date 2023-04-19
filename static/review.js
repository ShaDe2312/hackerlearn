/*const userMessages = [];

const userMessageForm = document.querySelector('form');
const userMessagesList = document.querySelector('ul');

function renderMessages() {
  let messageItems = '';
  for (const message of userMessages) {
    messageItems = `
      ${messageItems}
      <li class="message-item">
        
        <p>${message.user_name}</p> 

        <p>${message.text}</p>
      
        <div class="message-image">
          <img src="${message.image}" alt="image">
        </div>
        
       
      </li>
    `;
  }

  userMessagesList.innerHTML = messageItems;
}

function formSubmitHandler(event) {
  event.preventDefault();
  const userNameInput = event.target.querySelector('#user-name');
  const userMessageInput = event.target.querySelector('textarea');
  const messageImageInput = event.target.querySelector('#message-image');
  const userName = userNameInput.value;
  const userMessage = userMessageInput.value;
  const imageUrl = messageImageInput.value;

  if (
    !userMessage ||
    !imageUrl ||
    !userName ||
    userName.trim().length ===0||
    userMessage.trim().length === 0 ||
    imageUrl.trim().length === 0
  ) {
    alert('Please insert a valid message and image.');
    return;
  }

  userMessages.push({
    user_name: userName,
    text: userMessage,
    image: imageUrl,
  });

 userNameInput.value = '';
  userMessageInput.value = '';
  messageImageInput.value = '';

  renderMessages();
}

userMessageForm.addEventListener('submit', formSubmitHandler); */