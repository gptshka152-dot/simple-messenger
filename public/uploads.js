document.getElementById('avatar-upload').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('avatar', file);
  const response = await fetch('/upload-avatar', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  if (response.ok) {
    const data = await response.json();
    currentUser.avatar_url = data.avatar_url;
    alert('Avatar updated!');
  } else {
    alert('Avatar upload failed');
  }
});

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch('/upload-file', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  if (response.ok) {
    return await response.json();
  } else {
    throw new Error('File upload failed');
  }
}
