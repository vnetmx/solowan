/*

  as.h

  This file is part of OpenNOP-SoloWAN distribution.

  Copyright (C) 2014 Center for Open Middleware (COM) 
                     Universidad Politecnica de Madrid, SPAIN

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization 
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm. 

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad 
    Politecnica de Madrid which aims to experiment with open-source based WAN 
    optimization solutions.

  References:

    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    OpenNOP: http://www.opennop.org
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es   

  License:

    OpenNOP-SoloWAN is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP-SoloWAN is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/


#ifndef AS_H_
#define AS_H_

typedef void* as;   /* Tipo abstracto que representa la tabla
                       asociativa y que contiene un puntero
                       a la información necesaria.  */

int as_crear(as *pt, size_t nreg, size_t lvalor);
    /*	 Crea una tabla en memoria, dimensionada para "nreg" registros.
	 El valor retornado es 1 si no falla y 0 si falla.
	 Los registros son de longitud variable "lvalor" octetos */

int as_cerrar(as t);
    /*   Cerrar la tabla, liberando los recursos asignados a ella.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_leer(as t, const size_t pos, void* pv);
    /*   Lee el valor almacenado en la posicion pos. Si no existe
	 el registro, falla.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_escribir(as t, const size_t pos, const void* pv);
    /*   Escribe un registro, dada su posicion y el valor asociado.
         Si existe el valor en esa posicion, lo reescribe.
         El valor retornado es 1 si no falla y 0 si falla.  */

int as_borrar(as t, const size_t pos);
    /*   Borra un registro en la posicion pos.  El valor retornado es
         siempre 1 (suponemos que no falla).  */

int as_llenos(as t);
/*   Devuelve el numero de registros almacenados  */

#endif /* AS_H_ */
