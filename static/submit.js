document.querySelector('form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const grade = document.querySelector('input[name="grade"]:checked');
    const content = document.querySelector('textarea[name="content"]').value.trim();
    const messageDiv = document.getElementById('message');

    messageDiv.innerHTML = ''; // Use innerHTML to clear
    messageDiv.className = 'message';
    messageDiv.style.display = 'none';

    if (!grade) {
        showMessage('학년을 선택해주세요.', 'error');
        return;
    }
    if (!content) {
        showMessage('건의사항을 입력해주세요.', 'error');
        return;
    }

    const payload = {
        grade: grade.value,
        content: content
    };

    try {
        const response = await fetch('/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const text = await response.text();
            showMessage(`오류가 발생했습니다: ${text}`, 'error');
            return;
        }

        const data = await response.json();
        const suggestionId = data.id;
        const checkUrl = `/suggestion/${suggestionId}`;
        
        showMessage(
            `건의사항이 성공적으로 제출되었습니다. (ID: ${suggestionId}) <br><a href="${checkUrl}">여기</a>를 클릭하여 답변을 확인하세요.`, 
            'success'
        );
        document.querySelector('form').reset();

    } catch (error) {
        showMessage('제출 중 오류가 발생했습니다.', 'error');
        console.error(error);
    }
});

function showMessage(html, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.innerHTML = html;
    messageDiv.className = 'message ' + type;
    messageDiv.style.display = 'block';
}
