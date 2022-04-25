           const colors = [
                '#880E4F',
                '#4A148C',
                '#BD0232',
                '#C500FE',
                '#613A8F',
                '#fa215e',
                '#fd312a'
            ]


            function createSquare(){
                const section = document.querySelector('section');
                const square = document.createElement('span');

                var size = Math.random() * 50;
                square.style.width = 20 + size +'px';
                square.style.height = 20 + size +'px';
                square.style.left = Math.random() * innerWidth + 'px';
                square.style.top = Math.random() * innerHeight + 'px';

                const bg = colors[Math.floor(Math.random() * colors.length)]
                square.style.background = bg;

                section.appendChild(square);

                setTimeout(()=>{
                    square.remove()
                },5000)

            }
            setInterval(createSquare, 150)