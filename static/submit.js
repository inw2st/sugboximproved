document.querySelector('form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const grade = document.querySelector('input[name="grade"]:checked');
    const content = document.querySelector('textarea[name="content"]').value.trim();

    if (!grade) {
        alert('학년을 선택해주세요.');
        return;
    }
    if (!content) {
        alert('건의사항을 입력해주세요.');
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
            alert('오류가 발생했습니다: ' + text);
            return;
        }

        const data = await response.json();
        alert('건의사항이 제출되었습니다. ID: ' + data.id);

        document.querySelector('form').reset();
    } catch (error) {
        alert('제출 중 오류가 발생했습니다.');
        console.error(error);
    }
});
