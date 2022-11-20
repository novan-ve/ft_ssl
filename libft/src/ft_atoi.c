/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_atoi.c                                          :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/10/28 12:34:26 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 18:10:46 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_atoi(const char *str)
{
	int					factor;
	unsigned long long	result;
	unsigned long long	max;
	int					i;

	max = 9223372036854775807;
	result = 0;
	i = 0;
	while (str[i] == ' ' || (str[i] >= 9 && str[i] <= 13))
		i++;
	if (str[i] == '+' && str[i + 1] != '+' && str[i + 1] != '-')
		i++;
	factor = (str[i] == '-') ? -1 : 1;
	if (str[i] == '-')
		i++;
	while (str[i] >= '0' && str[i] <= '9')
	{
		if (factor == -1 && result > max)
			return (0);
		if (result > max)
			return (-1);
		result = result * 10 + str[i] - '0';
		i++;
	}
	return (factor * (int)result);
}
