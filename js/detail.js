function setIntroduction(title) {
  const introContainer = document.getElementById("detail-introduction");
  const introtitleEl = document.getElementById("detail-intr-title");
  const introDescEl = document.getElementById("detail-intr-desc");
  const introOther = document.getElementById("detail-other");
  let spices = title.split(":");
  let description;
  // 重置菜单状态
  const elements = document.getElementsByClassName("sidenav-head");
  for (let i = 0; i < elements.length; i++) {
    const element = elements[i];
    element.classList.remove("active");
  }
  //   设置详情标题
  introtitleEl.innerText = title;
  const regex = /参考章节(.*?)([,。，])/;
  // 一级目录展示内容设置
  if (spices.length == 1) {
    if ("children" in data[title]) {
      let html = "";

      html += "<h3>技术列表</h3>";
      Object.keys(data).forEach((k, i) => {
        if (k == title) {
          description = data[title]["description"];
          Object.keys(data[title]["children"]).forEach((item, index) => {
            html += `<p>${index + 1}. ${item}</p>`;
          });
          const activeHeader = document.getElementById(`access-${i + 1}`);
          activeHeader.classList.add("active");
        }
      });
      introOther.innerHTML = html;
    } else {
      Object.keys(data).forEach((k, i) => {
        if (k == title) {
          description = data[title]["description"];
          const activeHeader = document.getElementById(`access-${i + 1}`);
          activeHeader.classList.add("active");
        }
      });
      introOther.innerHTML = "";
    }
  } else if (spices.length == 2) {
    // 二级目录展示内容设置
    subData = data[spices[0]]["children"];
    let html = "";
    Object.keys(subData).forEach((k, j) => {
      if (k == spices[1]) {
        description = subData[k]["description"];
        const index = Object.keys(data).findIndex((item) => item == spices[0]);
        const activeHeader = document.getElementById(
          `access-${index + 1}-${j + 1}`
        );
        activeHeader.classList.add("active");
        if ("children" in subData[k]) {
          thirdData = subData[k]["children"];
          Object.keys(thirdData).forEach((key, index) => {
            html += `<h5>${index + 1}. ${key}</h5>`;
            let desc = "";
            if (typeof thirdData[key] == "string") {
              const p_list = thirdData[key].split("\n");
              p_list.forEach((item) => {
                // desc += `<p>${item}</p>`;
                const match = item.match(regex);
                if (match) {
                  const match_str = match[1];
                  const spices = item.split(match_str);
                  desc += `<p>${spices[0]}<a href="javascript:void(0)" onclick="setIntroduction('${match_str}')">${match_str}</a>${spices[1]}</p>`;
                } else {
                  desc += `<p>${item}</p>`;
                }
              });
            } else {
              Object.keys(thirdData[key]).forEach((item, i) => {
                desc += `<p style="font-weight: 600">${i + 1}）${item}</p>`;
                const match = thirdData[key][item].match(regex);
                if (match) {
                  const match_str = match[1];
                  const spices = thirdData[key][item].split(match_str);
                  desc += `<p>${spices[0]}<a href="javascript:void(0)" onclick="setIntroduction('${match_str}')">${match_str}</a>${spices[1]}</p>`;
                } else {
                  desc += `<p>${thirdData[key][item]}</p>`;
                }
              });
            }
            html += `<pre style="background-color: #fff; font-size: 16px; text-wrap: initial">${desc}</pre>`;
          });
        }
      }
    });
    introOther.innerHTML = html;
  }
  //   else {
  //     // 三级目录展示内容设置
  //     thirdData = data[spices[0]]["children"][spices[1]]["children"];
  //     Object.keys(thirdData).forEach((k, g) => {
  //       if (k == spices[2]) {
  //         description = thirdData[k];
  //         const i = Object.keys(data).findIndex((item) => item == spices[0]);
  //         const j = Object.keys(data[spices[0]]["children"]).findIndex(
  //           (item) => item == spices[1]
  //         );
  //         const activeHeader = document.getElementById(
  //           `access-${i + 1}-${j + 1}-${g + 1}`
  //         );
  //         activeHeader.classList.add("active");
  //       }
  //     });
  //   }
  let desc = "";
  const p_list = description.split("\n");
  p_list.forEach((item) => {
    const match = item.match(regex);
    if (match) {
      const match_str = match[1];
      const spices = item.split(match_str);
      desc += `<p>${spices[0]}<a href="javascript:void(0)" onclick="setIntroduction('${match_str}')">${match_str}</a>${spices[1]}</p>`;
    } else {
      desc += `<p>${item}</p>`;
    }
  });
  introDescEl.innerHTML = desc;
  //   if (typeof description == "string") {
  //   } else {
  //     let html = "";
  //     Object.keys(description).forEach((item, i) => {
  //       html += `<p>${i + 1}）${item}</p>`;
  //       html += `<p>${description[item]}</p>`;
  //     });
  //     introDescEl.innerHTML = html;
  //   }
}

function toDetail(title) {
  parent.postMessage({ action: "loadContent", title: title }, "*");
  // parent.postMessage({ action: "setIntro", title: title }, "*");
}
