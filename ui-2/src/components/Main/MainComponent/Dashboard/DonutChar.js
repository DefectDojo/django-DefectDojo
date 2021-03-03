import React from "react";
import { Doughnut } from "react-chartjs-2";
function DonutChar() {
  return (
    <div>
      <Doughnut
        data={{
          labels: ["Critical", "High", "Medium", "Low", "Informational"],
          datasets: [
            {
              backgroundColor: [
                "#8c0000",
                "#f0ad4e",
                "#f0de28",
                "#337ab7",
                "#E0E0E0",
              ],
              data: [10, 20, 40, 20, 10],
            },
          ],
        }}
      />
    </div>
  );
}

export default DonutChar;
